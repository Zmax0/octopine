{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

module Server.Transport.Stream (start, startWithContext) where

import Common.Config (ServerConfig (..), SslConfig, initTlsParams, loadServerCredential)
import Common.Exception (AppExceptionKind (ExternalError, InvariantError), handleException, throwApp)
import Common.Logger (debug_, error_, info_, loggers, trace_)
import Common.Util (sockAddrFamily)
import Control.Concurrent (forkFinally)
import Control.Concurrent.Async (concurrently, race)
import qualified Control.Exception as E
import Control.Monad (forever, void, when)
import qualified Control.Monad.Catch as MC
import Control.Monad.Trans.State.Strict (runStateT)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Data.Foldable (for_)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (isNothing)
import Data.Text (Text)
import qualified Data.Text as T
import Formatting (format, (%))
import Formatting.Formatters (int)
import GHC.Conc (labelThread, myThreadId)
import GHC.Conc.Sync (showThreadId)
import GHC.Word (Word16)
import qualified Network.QUIC as QUIC
import qualified Network.QUIC.Server as QUIC.Server
import Network.Socket (AddrInfo (..), AddrInfoFlag (AI_PASSIVE), SockAddr, Socket, SocketOption (ReuseAddr), SocketType (Datagram, Stream), accept, bind, close, defaultHints, defaultProtocol, getAddrInfo, listen, openSocket, setSocketOption)
import qualified Network.Socket
import Network.Socket.Address (connect)
import qualified Network.TLS as TLS
import qualified Network.WebSockets as WS
import qualified Network.WebSockets.Stream as WS.Stream
import Server.Protocol (RelayFrame (OpenTcp, TcpData, UdpData), ServerCodec (decode, encode), ServerProtocol (label, newServerCodec, newServerContext))
import Server.Transport.Channel (Channel (next), quicChannel, split, tcpChannel, tlsChannel, udpChannel, wsChannel)
import Server.Transport.Transport (closePeer)
import Time (sec, timeout)

$(loggers "Server" ['debug_, 'info_, 'trace_, 'error_])

start :: forall context codec. (ServerProtocol context codec) => ServerConfig -> IO ()
start config = do
  context <- newServerContext config :: IO context
  startWithContext context config

startWithContext :: (ServerProtocol context codec) => context -> ServerConfig -> IO ()
startWithContext context config = do
  let host' = host config
      port' = port config
      maybeWs = ws config
      maybeQuic = quic config
      quic' =
        for_ maybeQuic $ \sslConfig -> do
          datagramSocket' <- datagramSocket host' port'
          startQuic context datagramSocket' sslConfig
  maybeTls <- initTlsParams $ ssl config
  streamSocket' <- streamSocket host' port'
  let tcp = case (maybeTls, maybeWs) of
        (Nothing, Nothing) -> startTcp context streamSocket'
        (Just tlsParams, Nothing) -> startTls context streamSocket' tlsParams
        (Nothing, Just _) -> startWs context streamSocket'
        (Just tlsParams, Just _) -> startWss context streamSocket' tlsParams
  _ <- concurrently quic' tcp
  return ()

type Endpoint a = (a, SockAddr)

data RelayClose = ClientClose | PeerClose deriving (Eq)

_finally :: IO (Maybe RelayClose) -> IO () -> IO ()
_finally relay' closeClient = do
  closeSource <- E.finally (relay') (MC.handleAll (handleException _error_) closeClient)
  _info_ $ case closeSource of Just ClientClose -> ("client* close" :: String); _ -> "client close"

_loop :: Socket -> (Endpoint Socket -> IO ()) -> IO ()
_loop socket handle =
  forever $
    E.bracketOnError (accept socket) (close . fst) $
      \inbound@(conn, addr) -> do
        void $
          forkFinally
            ( do
                thread <- myThreadId
                labelThread thread $ showThreadId thread ++ " - " ++ show addr ++ " . "
                MC.handleAll (handleException _error_) $ handle inbound
            )
            (const $ close conn)

startTcp :: (ServerProtocol context codec) => context -> Socket -> IO ()
startTcp context socket = do
  _info_ $ "start server => tcp|" ++ label context
  _loop socket $ \client -> _finally (relay client tcpChannel context) (return ())

-- trace_ "Tls" (return str)
startTls :: (ServerProtocol context codec) => context -> Socket -> TLS.ServerParams -> IO ()
startTls context socket tlsParams' = do
  _info_ $ "start server => tls|" ++ label context
  _loop socket $ \(conn, addr') -> do
    ctx <- initTlsContext conn tlsParams'
    _finally (relay (ctx, addr') tlsChannel context) (TLS.bye ctx)

startWs :: (ServerProtocol context codec) => context -> Socket -> IO ()
startWs context socket = do
  _info_ $ "start server => ws|" ++ label context
  let wsOptions = WS.defaultConnectionOptions
  _loop socket $ \(conn, addr') -> do
    conn' <- WS.acceptRequest =<< WS.makePendingConnection conn wsOptions
    _finally (relay (conn', addr') wsChannel context) (closeWs conn')

startWss :: (ServerProtocol context codec) => context -> Socket -> TLS.ServerParams -> IO ()
startWss context socket tlsParams' = do
  _info_ $ "start server => wss|" ++ label context
  let wsOptions = WS.defaultConnectionOptions
  _loop socket $ \(conn, addr') -> do
    tlsContext <- initTlsContext conn tlsParams'
    E.finally
      ( do
          conn' <- WS.acceptRequest =<< makePendingConnection tlsContext wsOptions
          E.catchJust
            (\case WS.CloseRequest _ _ -> Just (); _ -> Nothing)
            ( do
                closeSource <- relay (conn', addr') wsChannel context
                _info_ $ case closeSource of Just ClientClose -> ("client* close" :: String); _ -> "client close"
                closeWs conn'
            )
            (const $ return ())
      )
      (TLS.bye tlsContext)
  where
    makePendingConnection tlsContext wsOptions = do
      WS.Stream.makeStream (_recvData tlsContext) (maybe (return ()) (TLS.sendData tlsContext))
        >>= (`WS.makePendingConnectionFromStream` wsOptions)
    _recvData tlsContext =
      E.catch
        ( do
            next' <- TLS.recvData tlsContext
            if B.null next' then return Nothing else return (Just next')
        )
        ( \case
            TLS.PostHandshake TLS.Error_EOF -> return Nothing
            e -> E.throwIO e
        )

closeWs :: WS.Connection -> IO ()
closeWs conn' =
  E.catchJust
    (\case WS.CloseRequest _ _ -> Just (); WS.ConnectionClosed -> Just (); _ -> Nothing)
    (WS.sendClose conn' ("Bye" :: Text) >> void (WS.receiveDataMessage conn'))
    (const return ())

startQuic :: (ServerProtocol context codec) => context -> Socket -> SslConfig -> IO ()
startQuic context socket sslConfig = do
  _info_ $ "start server => quic|" ++ label context
  credentials <- loadServerCredential sslConfig
  let serverConfig =
        QUIC.Server.defaultServerConfig
          { QUIC.Server.scCredentials = credentials,
            QUIC.Server.scALPN = Just (\_ _ -> return "http/1.1")
          }
  QUIC.Server.runWithSockets [socket] serverConfig $
    \conn -> forever $
      MC.handleAll (handleException _error_) $
        E.bracketOnError (QUIC.acceptStream conn) QUIC.closeStream $
          \stream -> do
            addr' <- QUIC.remoteSockAddr <$> QUIC.getConnectionInfo conn
            void $
              forkFinally
                (MC.handleAll (handleException _error_) $ _finally (relay (stream, addr') quicChannel context) (return ()))
                (const $ QUIC.closeStream stream)

initTlsContext :: Socket -> TLS.ServerParams -> IO TLS.Context
initTlsContext socket params = do
  ctx <- TLS.contextNew socket params
  let logging = TLS.defaultLogging {TLS.loggingPacketSent = trace_ "Tls" . return, TLS.loggingPacketRecv = trace_ "Tls" . return}
  TLS.contextHookSetLogging ctx logging
  TLS.handshake ctx
  return ctx

relay :: (ServerProtocol context codec) => Endpoint client -> Channel IO client client StrictByteString -> context -> IO (Maybe RelayClose)
relay (client, clientAddr) clientChannel context = do
  loop B.empty (client, clientAddr) clientChannel context
  where
    loop pending (client', clientAddr') clientChannel' context' = do
      chunk <- next clientChannel' client'
      if B.null chunk
        then return Nothing
        else do
          let pending' = pending <> chunk
          newServerCodec' <- newServerCodec context' pending'
          case newServerCodec' of
            Left e -> E.throwIO e
            Right Nothing -> loop pending' (client', clientAddr') clientChannel' context'
            Right (Just (leftover, peerFrames, codec)) ->
              E.catch @E.IOException
                (_relay (leftover, peerFrames, codec) (client', clientAddr') clientChannel')
                ((>> return Nothing) . _info_ . (("relay failed, " ++) . show))

_relay :: (ServerCodec codec) => (StrictByteString, [RelayFrame], codec) -> Endpoint client -> Channel IO client client StrictByteString -> IO (Maybe RelayClose)
_relay (leftover, pending, codec) (client, clientAddr) clientChannel = do
  thread <- myThreadId
  res <- case pending of
    OpenTcp peerAddr : rest -> do
      labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr ++ " - " ++ show peerAddr
      let openPeer = do
            peer <- Network.Socket.socket (sockAddrFamily peerAddr) Stream defaultProtocol
            bind peer =<< Network.Socket.getSocketName peer
            localAddr <- Network.Socket.getSocketName peer
            _info_ $ "new stream relay, local=" ++ show localAddr ++ ", peer=" ++ show peerAddr
            return peer
      E.bracketOnError openPeer (closePeer False) $ \peer -> do
        connected <- timeout (sec 10) $ connect peer peerAddr
        when (isNothing connected) $ throwApp ExternalError "connect peer timeout"
        closeSource <- biForwardTcp (leftover, rest, codec) (client, clientAddr) (peer, peerAddr) clientChannel tcpChannel
        closePeer (closeSource == PeerClose) peer
        return $ Just closeSource
    UdpData _ peerAddr : _ -> do
      labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr
      let family = sockAddrFamily peerAddr
          openPeer = do
            peer <- Network.Socket.socket family Datagram defaultProtocol
            bind peer =<< Network.Socket.getSocketName peer
            localAddr <- Network.Socket.getSocketName peer
            _info_ $ "new datagram relay, local=" ++ show localAddr
            return peer
      E.bracketOnError openPeer (closePeer False) $ \peer -> do
        void $ biForwardUdp (leftover, pending, codec) (client, clientAddr) peer clientChannel udpChannel
        closePeer False peer
        return Nothing
    TcpData {} : _ -> throwApp InvariantError "expect a OpenTcp RelayFrame for the first reading"
    [] -> throwApp InvariantError "empty peer payload"
  return res

-- | Left peerToClient
-- | Right clientToPeer
biForwardTcp :: (ServerCodec codec) => (StrictByteString, [RelayFrame], codec) -> Endpoint client -> Endpoint peer -> Channel IO client client StrictByteString -> Channel IO peer peer StrictByteString -> IO RelayClose
biForwardTcp (leftover, pending, codec) (client, clientAddr) (peer, peerAddr) clientChannel peerChannel = do
  let (clientNext, clientSend) = split clientChannel
      (peerNext, peerSend) = split peerChannel
      peerToClient = recvTcpPeerSendClient codec (peer, peerAddr) (client, clientAddr) peerNext clientSend
      clientToPeer = recvClientSendTcpPeer (leftover, pending, codec) (client, clientAddr) (peer, peerAddr) clientNext peerSend
  result <- race peerToClient clientToPeer
  return $ case result of Left () -> PeerClose; Right () -> ClientClose

-- | Left peerToClient
-- | Right clientToPeer
biForwardUdp :: (ServerCodec codec) => (StrictByteString, [RelayFrame], codec) -> Endpoint client -> Socket -> Channel IO client client StrictByteString -> Channel IO Socket Socket (StrictByteString, SockAddr) -> IO (Either () ())
biForwardUdp (leftover, pending, codec) (client, clientAddr) peer clientChannel peerChannel = do
  let (clientNext, clientSend) = split clientChannel
      (peerNext, peerSend) = split peerChannel
      peerToClient = recvUdpPeerSendClient codec peer (client, clientAddr) peerNext clientSend
      clientToPeer = recvClientSendUdpPeer (leftover, pending, codec) (client, clientAddr) peer clientNext peerSend
  race peerToClient clientToPeer

-- | peer (next) -> client (send)
recvTcpPeerSendClient :: (ServerCodec codec) => codec -> Endpoint peer -> Endpoint client -> (peer -> IO StrictByteString) -> (client -> StrictByteString -> IO ()) -> IO ()
recvTcpPeerSendClient codec (peer, peerAddr) (client, clientAddr) peerNext clientSend = do
  thread <- myThreadId
  labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr ++ " < " ++ show peerAddr
  chunk <- peerNext peer
  if B.null chunk
    then _debug_ ("recv FIN" :: String)
    else do
      _debug_ $ format ("recv " % int % " bytes") (B.length chunk)
      (encoded, codec') <- runStateT (encode $ TcpData chunk) codec
      _debug_ $ format ("encode " % int % " bytes") (B.length encoded)
      clientSend client encoded
      _debug_ $ format ("send " % int % " bytes") (B.length encoded)
      recvTcpPeerSendClient codec' (peer, peerAddr) (client, clientAddr) peerNext clientSend

-- | peer (next) -> client (send)
recvUdpPeerSendClient :: (ServerCodec codec) => codec -> Socket -> Endpoint client -> (Socket -> IO (StrictByteString, SockAddr)) -> (client -> StrictByteString -> IO ()) -> IO ()
recvUdpPeerSendClient codec peer (client, clientAddr) peerNext clientSend = do
  thread <- myThreadId
  (chunk, peerAddr) <- peerNext peer
  labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr ++ " < " ++ show peerAddr
  _debug_ $ format ("recv " % int % " bytes") (B.length chunk)
  (encoded, codec') <- runStateT (encode $ UdpData chunk peerAddr) codec
  _debug_ $ format ("encode " % int % " bytes") (B.length encoded)
  clientSend client encoded
  _debug_ $ format ("send " % int % " bytes") (B.length encoded)
  recvUdpPeerSendClient codec' peer (client, clientAddr) peerNext clientSend

-- | client (next) -> peer (send)
recvClientSendTcpPeer :: (ServerCodec codec) => (StrictByteString, [RelayFrame], codec) -> Endpoint client -> Endpoint peer -> (client -> IO StrictByteString) -> (peer -> StrictByteString -> IO ()) -> IO ()
recvClientSendTcpPeer (leftover, pending, codec) (client, clientAddr) (peer, peerAddr) clientNext peerSend = do
  thread <- myThreadId
  labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr ++ " > " ++ show peerAddr
  for_ pending $ \payload -> do
    case payload of
      TcpData msg -> do
        peerSend peer msg
        _debug_ $ format ("send pending " % int % " bytes") (B.length msg)
      _ -> throwApp InvariantError $ "expected TCP peer payload, actual: " ++ show payload
  _recvClientSendTcpPeer codec leftover (client, clientAddr) (peer, peerAddr) clientNext peerSend

_recvClientSendTcpPeer :: (ServerCodec codec) => codec -> StrictByteString -> Endpoint client -> Endpoint peer -> (client -> IO StrictByteString) -> (peer -> StrictByteString -> IO ()) -> IO ()
_recvClientSendTcpPeer codec leftover (client, clientAddr) (peer, peerAddr) clientNext peerSend = do
  chunk <- if B.null leftover then clientNext client else return B.empty
  let input = leftover <> chunk
  if B.null input
    then _debug_ ("recv FIN" :: String)
    else do
      _debug_ $ format ("recv " % int % " bytes (leftover " % int % " bytes)") (B.length chunk) (B.length leftover)
      (res, codec') <- runStateT (decode input) codec
      case res of
        Left e -> handleException _error_ e
        Right Nothing -> do
          chunk' <- clientNext client
          if B.null chunk'
            then _debug_ ("recv FIN" :: String)
            else do
              _debug_ $ format ("recv " % int % " bytes (leftover " % int % " bytes)") (B.length chunk') (B.length input)
              _recvClientSendTcpPeer codec (input <> chunk') (client, clientAddr) (peer, peerAddr) clientNext peerSend
        Right (Just (leftover', TcpData msg)) -> do
          _debug_ $ format ("decode " % int % " bytes") (B.length msg)
          peerSend peer msg
          _debug_ $ format ("send " % int % " bytes") (B.length msg)
          _recvClientSendTcpPeer codec' leftover' (client, clientAddr) (peer, peerAddr) clientNext peerSend
        Right (Just (_, payload)) -> throwApp InvariantError $ "expected TCP peer payload, actual: " ++ show payload

-- | client (next) -> peer (send)
recvClientSendUdpPeer :: (ServerCodec codec) => (StrictByteString, [RelayFrame], codec) -> Endpoint client -> Socket -> (client -> IO StrictByteString) -> (Socket -> (StrictByteString, SockAddr) -> IO ()) -> IO ()
recvClientSendUdpPeer (leftover, pending, codec) (client, clientAddr) peer clientNext peerSend = do
  thread <- myThreadId
  for_ pending $ \payload -> do
    case payload of
      UdpData msg peerAddr -> do
        labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr ++ " > " ++ show peerAddr
        peerSend peer (msg, peerAddr)
        _debug_ $ format ("send pending " % int % " bytes") (B.length msg)
      _ -> throwApp InvariantError $ "expected UDP peer payload, actual: " ++ show payload
  _recvClientSendUdpPeer codec leftover (client, clientAddr) peer clientNext peerSend

_recvClientSendUdpPeer :: (ServerCodec codec) => codec -> StrictByteString -> Endpoint client -> Socket -> (client -> IO StrictByteString) -> (Socket -> (StrictByteString, SockAddr) -> IO ()) -> IO ()
_recvClientSendUdpPeer codec leftover (client, clientAddr) peer clientNext peerSend = do
  thread <- myThreadId
  chunk <- if B.null leftover then clientNext client else return B.empty
  let input = leftover <> chunk
  if B.null input
    then _debug_ ("recv FIN" :: String)
    else do
      _debug_ $ format ("recv " % int % " bytes (leftover " % int % " bytes)") (B.length chunk) (B.length leftover)
      (res, codec') <- runStateT (decode input) codec
      case res of
        Left e -> handleException _error_ e
        Right Nothing -> do
          chunk' <- clientNext client
          if B.null chunk'
            then _debug_ ("recv FIN" :: String)
            else do
              _debug_ $ format ("recv " % int % " bytes (leftover " % int % " bytes)") (B.length chunk') (B.length input)
              _recvClientSendUdpPeer codec (input <> chunk') (client, clientAddr) peer clientNext peerSend
        Right (Just (leftover', UdpData msg peerAddr)) -> do
          labelThread thread $ showThreadId thread ++ " - " ++ show clientAddr ++ " > " ++ show peerAddr
          _debug_ $ format ("decode " % int % " bytes") (B.length msg)
          peerSend peer (msg, peerAddr)
          _debug_ $ format ("send " % int % " bytes") (B.length msg)
          _recvClientSendUdpPeer codec' leftover' (client, clientAddr) peer clientNext peerSend
        Right (Just (_, payload)) -> throwApp InvariantError $ "expected UDP peer payload, actual: " ++ show payload

streamSocket :: Text -> Word16 -> IO Socket
streamSocket host' port' = do
  let hints = defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Stream}
  addr <- NE.head <$> getAddrInfo (Just hints) (Just $ T.unpack host') (Just $ show port')
  socket <- openSocket addr
  setSocketOption socket ReuseAddr 1
  bind socket $ addrAddress addr
  listen socket 4096
  return socket

datagramSocket :: Text -> Word16 -> IO Socket
datagramSocket host' port' = do
  let hints = defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Datagram}
  addr <- NE.head <$> getAddrInfo (Just hints) (Just $ T.unpack host') (Just $ show port')
  socket <- openSocket addr
  setSocketOption socket ReuseAddr 1
  bind socket $ addrAddress addr
  return socket
