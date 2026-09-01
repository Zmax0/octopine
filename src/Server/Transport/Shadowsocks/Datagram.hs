{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

module Server.Transport.Shadowsocks.Datagram (start) where

import Common.Config (ServerConfig (host, port))
import Common.Exception (AppExceptionKind (InvariantError, ProtocolError), handleException, throwApp)
import Common.Logger (debug_, error_, info_, loggers, trace_)
import Common.Protocol.Shadowsocks (Mode (Server))
import Common.Protocol.Shadowsocks.Aead2022 (isAead2022)
import Common.Protocol.Shadowsocks.PacketWindowFilter (PacketWindowFilter)
import qualified Common.Protocol.Shadowsocks.PacketWindowFilter as PacketWindowFilter
import qualified Common.Protocol.Shadowsocks.UDP.Session as UdpSession
import Common.Util (sockAddrFamily)
import Control.Concurrent.Async (Async, async, cancel, race, withAsync)
import Control.Concurrent.STM (TBQueue, atomically, newEmptyTMVar, newTBQueue, putTMVar, readTBQueue, takeTMVar, writeTBQueue)
import qualified Control.Exception as E
import Control.Lens ((&), (.~), (^.))
import Control.Monad (forever, unless)
import qualified Control.Monad.Catch as MC
import Control.Monad.Trans.State (runState)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import qualified Data.Cache.LRU as LRU
import qualified Data.Cache.LRU.IO as LRU.IO
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word64)
import Formatting (format, (%))
import Formatting.Formatters (int)
import GHC.Conc (labelThread, myThreadId)
import GHC.Conc.Sync (showThreadId)
import Network.Socket (AddrInfo (addrAddress), AddrInfoFlag (AI_PASSIVE), SockAddr, Socket, SocketOption (ReuseAddr), SocketType (Datagram), addrFlags, addrSocketType, bind, close, defaultHints, defaultProtocol, getAddrInfo, openSocket, setSocketOption)
import qualified Network.Socket
import Server.Protocol (RelayFrame (UdpData))
import qualified Server.Protocol.Shadowsocks.Codec as Shadowsocks
import qualified Server.Transport.Channel as Channel
import Server.Transport.Transport (closePeer)
import System.Clock (Clock (Monotonic), TimeSpec (TimeSpec), getTime)
import Time (minute, threadDelay)
import Time.Units (Second, Time, floorRat, sec)

$(loggers "Server" ['debug_, 'info_, 'trace_, 'error_])

data CacheKey = SessionKey Word64 | ClientKey SockAddr deriving (Eq, Ord, Show)

data ClientPacket = ClientPacket StrictByteString SockAddr UdpSession.Session

type Worker = Async ()

data Associate = Associate (TBQueue ClientPacket) Worker

data CacheEntry = CacheEntry Associate TimeSpec

data Cache = Cache (LRU.IO.AtomicLRU CacheKey CacheEntry) (Time Second)

_next :: Socket -> IO (StrictByteString, SockAddr)
_send :: Socket -> (StrictByteString, SockAddr) -> IO ()
(_next, _send) = Channel.split Channel.udpChannel

queueSize :: Int
queueSize = 1024

cacheSize :: Int
cacheSize = 10240

ttl :: Time Second
ttl = sec 300

-- |
-- UDP server thread model:
--
-- @
-- [1] UDP service
--     |
--     +-- [2] relay (one global thread)
--     |       receive client datagram from the server UDP socket
--     |       |
--     |       +-- [4] find or create `Associate` (n threads)
--     |               |
--     |               +-- [5] TBQueue (queueSize)
--     |                       ^
--     |                       |
--     |                       | client datagram (relay)
--     |                       |
--     |                       +-- [6] worker in `_loop`
--     |                              race readTBQueue and read peer socket
--     |                              process one direction per iteration
--     |                              cancel the other read after race
--     |                              |
--     |                              +- client datagram: send to peer
--     |                              |
--     |                              +- peer datagram: encode and send to client
--     |
--     +-- [3] cleanup (one global thread)
--             every ttl minutes, cancel expired associates
--
-- Threads = 1 relay + 1 cleanup + N * 1 worker
--         = 2 + N long-lived GHC lightweight threads
-- (race creates short-lived competing branches for each loop iteration.)
-- @
start :: String -> ServerConfig -> Shadowsocks.PacketCodec -> IO ()
start label' config codec = do
  let hints = defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Datagram}
  addr <- NE.head <$> getAddrInfo (Just hints) (Just $ T.unpack $ host config) (Just $ show $ port config)
  server <- E.bracketOnError (openSocket addr) close $ \socket -> do
    setSocketOption socket ReuseAddr 1
    bind socket $ addrAddress addr
    return socket
  entries <- LRU.IO.newAtomicLRU $ Just $ fromIntegral cacheSize
  let cache = Cache entries ttl
  withAsync
    ( do
        thread <- myThreadId
        labelThread thread "Server.Shadowsocks.Cleanup"
        forever $ MC.handleAll (handleException _error_) $ do
          threadDelay $ minute 3
          now <- getTime Monotonic
          cancelAssociates =<< takeExpiredAssociates cache now
    )
    $ \cleanup ->
      E.finally
        ( do
            _info_ $ "start server => udp|" ++ label'
            relay codec server cache
        )
        ( do
            cancel cleanup
            entries' <- LRU.IO.toList entries
            cancelAssociates [associate | (_, CacheEntry associate _) <- entries']
            close server
            _info_ $ "server shutdown => udp|" ++ label'
        )

relay :: Shadowsocks.PacketCodec -> Socket -> Cache -> IO ()
relay codec@(Shadowsocks.PacketCodec kind _ _) client cache = do
  forever $ MC.handleAll (handleException _error_) $ do
    (msg, clientAddr) <- _next client
    thread <- myThreadId
    labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr
    _debug_ $ format ("recv " % int % " bytes") (B.length msg)
    decoded <- Shadowsocks.decodeDatagram codec msg
    case decoded of
      Left exception -> E.throwIO exception
      Right Nothing -> throwApp ProtocolError "decode failed, empty packet"
      Right (Just decoded') -> do
        (payload, peerAddr, key, sessionId, session) <- case decoded' of
          Shadowsocks.DecodedDatagram _ (UdpData payload' peerAddr') session' ->
            let (key, sessionId) =
                  if isAead2022 kind
                    then
                      let UdpSession.Session clientSessionId _ _ _ = session'
                       in (SessionKey clientSessionId, clientSessionId)
                    else (ClientKey clientAddr, 0)
             in return (payload', peerAddr', key, sessionId, session')
          Shadowsocks.DecodedDatagram _ frame _ -> throwApp InvariantError ("decode failed, expected UdpData, actual: " ++ show frame)
        let packet = ClientPacket payload peerAddr session
        now <- getTime Monotonic
        associate <- touchAssociate cache key now
        case associate of
          Just (Associate events _) -> atomically $ writeTBQueue events packet
          Nothing -> do
            session' <- newSession sessionId
            Associate events _ <- newAssociate (isAead2022 kind) codec client cache key clientAddr peerAddr session' now
            atomically $ writeTBQueue events packet

newSession :: Word64 -> IO UdpSession.Session
newSession clientSessionId' = do
  session <- UdpSession.new Server
  return $ session & UdpSession.clientSessionId .~ clientSessionId'

touchAssociate :: Cache -> CacheKey -> TimeSpec -> IO (Maybe Associate)
touchAssociate (Cache entries _) key now = do
  result <- newIORef Nothing
  LRU.IO.modifyAtomicLRU'
    ( \current -> case LRU.lookup key current of
        (_, Nothing) -> return current
        (refreshed, Just (CacheEntry associate _)) -> do
          writeIORef result $ Just associate
          return $ LRU.insert key (CacheEntry associate now) refreshed
    )
    entries
  readIORef result

newAssociate :: Bool -> Shadowsocks.PacketCodec -> Socket -> Cache -> CacheKey -> SockAddr -> SockAddr -> UdpSession.Session -> TimeSpec -> IO Associate
newAssociate isAead2022' codec client cache@(Cache entries _) key clientAddr peerAddr session now = E.mask $ \restore -> do
  E.bracketOnError
    (Network.Socket.socket (sockAddrFamily peerAddr) Datagram defaultProtocol)
    (closePeer False)
    $ \peer -> do
      bind peer =<< Network.Socket.getSocketName peer
      localAddr <- Network.Socket.getSocketName peer
      _info_ $ "new datagram, local=" ++ show localAddr
      events <- atomically $ newTBQueue $ fromIntegral queueSize
      ready <- atomically newEmptyTMVar
      worker <-
        async $
          E.finally
            ( MC.handleAll (handleException _error_) $ do
                atomically $ takeTMVar ready
                _loop codec client cache key peer events clientAddr session (if isAead2022' then Just PacketWindowFilter.empty else Nothing)
            )
            (LRU.IO.modifyAtomicLRU (\current -> fst $ LRU.delete key current) entries)
      let associate = Associate events worker
      associatesToClose <-
        E.onException
          ( do
              expired <- takeExpiredAssociates cache now
              evicted <- newIORef Nothing
              LRU.IO.modifyAtomicLRU'
                ( \current -> do
                    let (remaining, entry) = LRU.insertInforming key (CacheEntry associate now) current
                    writeIORef evicted entry
                    return remaining
                )
                entries
              entry <- readIORef evicted
              return $ expired ++ [evictedAssociate | Just (_, CacheEntry evictedAssociate _) <- [entry]]
          )
          (cancel worker)
      atomically $ putTMVar ready ()
      restore $ cancelAssociates associatesToClose
      _trace_ $ ("new associate" :: Text)
      return associate

_loop :: Shadowsocks.PacketCodec -> Socket -> Cache -> CacheKey -> Socket -> TBQueue ClientPacket -> SockAddr -> UdpSession.Session -> Maybe PacketWindowFilter -> IO ()
_loop codec client cache key peer events clientAddr session packetWindow = do
  event <- race (atomically $ readTBQueue events) (_next peer)
  now <- getTime Monotonic
  active <- maybe False (const True) <$> touchAssociate cache key now
  unless active $ throwApp InvariantError "UDP associate is no longer active while handling a datagram"
  case event of
    Left (ClientPacket payload peerAddr incomingSession) -> do
      thread <- myThreadId
      labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr ++ " > " ++ show peerAddr
      packetWindow' <- case packetWindow of
        Nothing -> return Nothing
        Just currentWindow -> do
          let UdpSession.Session _ _ packetId _ = incomingSession
              (valid, nextWindow) = runState (PacketWindowFilter.validate packetId maxBound) currentWindow
          unless valid $ throwApp ProtocolError ("UDP packet ID is duplicated or outside the sliding window: " ++ show packetId)
          return $ Just nextWindow
      session' <- updateSession codec session incomingSession
      _send peer (payload, peerAddr)
      _debug_ $ format ("send " % int % " bytes") (B.length payload)
      _loop codec client cache key peer events clientAddr session' packetWindow'
    Right (payload, peerAddr) -> do
      thread <- myThreadId
      labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr ++ " < " ++ show peerAddr
      (encoded, session') <- Shadowsocks.encodeDatagram codec session $ UdpData payload peerAddr
      _debug_ $ format ("encode " % int % " bytes") (B.length encoded)
      _send client (encoded, clientAddr)
      _debug_ $ format ("send " % int % " bytes") (B.length encoded)
      _loop codec client cache key peer events clientAddr session' packetWindow

updateSession :: Shadowsocks.PacketCodec -> UdpSession.Session -> UdpSession.Session -> IO UdpSession.Session
updateSession (Shadowsocks.PacketCodec kind _ _) current incoming
  | not $ isAead2022 kind = do
      _debug_ $ "recv from client; session=" ++ show current
      return current
  | current ^. UdpSession.clientSessionId /= incoming ^. UdpSession.clientSessionId =
      throwApp InvariantError "incoming UDP session does not match associate"
  | otherwise = do
      let UdpSession.Session clientSessionId _ _ user = incoming
          UdpSession.Session _ serverSessionId serverPacketId _ = current
          session = UdpSession.Session clientSessionId serverSessionId serverPacketId user
      _debug_ $ "recv from client; session=" ++ show session
      return session

takeExpiredAssociates :: Cache -> TimeSpec -> IO [Associate]
takeExpiredAssociates (Cache entries ttlSeconds) now = do
  result <- newIORef []
  LRU.IO.modifyAtomicLRU'
    ( \current -> do
        let (active, expired) =
              foldr
                ( \(key, CacheEntry associate lastUsed) (active', expired') ->
                    if lastUsed + TimeSpec (floorRat ttlSeconds) 0 <= now
                      then (fst $ LRU.delete key active', associate : expired')
                      else (active', expired')
                )
                (current, [])
                $ LRU.toList current
        writeIORef result expired
        return active
    )
    entries
  readIORef result

cancelAssociates :: [Associate] -> IO ()
cancelAssociates [] = return ()
cancelAssociates associates = do
  _trace_ $ ("cancel associates" :: Text)
  mapM_ (\(Associate _ worker) -> cancel worker) associates
