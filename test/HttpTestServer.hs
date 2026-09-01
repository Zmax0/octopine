module HttpTestServer (start) where

import Codec.Binary.UTF8.Generic (toString)
import Control.Concurrent.Async (wait, withAsync)
import Control.Monad (forever, unless)
import qualified Data.ByteString.Char8 as S
import Data.ByteString.UTF8 (fromString)
import qualified Data.List.NonEmpty as NE
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.Socket (AddrInfo (addrAddress, addrFlags, addrSocketType), AddrInfoFlag (..), Socket, SocketType (..), accept, bind, defaultHints, getAddrInfo, gracefulClose, listen, openSocket)
import Network.Socket.ByteString (recv, sendAll)
import Time (floorRat, ms)

start :: IO ()
start = do
  let hints = defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Stream}
  addr <- NE.head <$> getAddrInfo (Just hints) (Just "172.27.77.53") (Just "51099")
  socket <- openSocket addr
  bind socket $ addrAddress addr
  listen socket 5
  echo socket

echo :: Socket -> IO ()
echo s = forever $ do
  (conn, _addr) <- accept s
  withAsync (doEcho conn) wait
  where
    doEcho :: Socket -> IO ()
    doEcho socket = do
      msg <- Network.Socket.ByteString.recv socket 1024
      unless (S.null msg) $ do
        putStr $ toString msg
        time <- getPOSIXTime
        let millis = round (time * 1000) :: Integer
        Network.Socket.ByteString.sendAll socket $ responseHtml millis
        gracefulClose socket $ floorRat $ ms 1000

responseHtml :: Integer -> S.ByteString
responseHtml time = fromString $ "HTTP/1.1 200 OK\r\nServer: HttpTestServer\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" ++ "<h1>" ++ show time ++ "</h1>\r\n"
