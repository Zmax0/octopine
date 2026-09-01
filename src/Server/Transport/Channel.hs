module Server.Transport.Channel (Channel (next, send), tcpChannel, tlsChannel, wsChannel, quicChannel, udpChannel, split, reunite) where

import Control.Monad.IO.Class (MonadIO)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import qualified Network.QUIC as QUIC
import Network.Socket (SockAddr, Socket)
import qualified Network.Socket.ByteString
import qualified Network.TLS as TLS
import qualified Network.WebSockets as WS

streamRecvChunkSize :: Int
streamRecvChunkSize = 4096

packetRecvSize :: Int
packetRecvSize = 65535

tlsNext :: (MonadIO m) => TLS.Context -> m StrictByteString
tlsNext = TLS.recvData

tlsSend :: (MonadIO m) => TLS.Context -> StrictByteString -> m ()
tlsSend context' data' = TLS.sendData context' $ B.fromStrict data'

tcpNext :: Socket -> IO StrictByteString
tcpNext socket' = Network.Socket.ByteString.recv socket' streamRecvChunkSize

tcpSend :: Socket -> StrictByteString -> IO ()
tcpSend = Network.Socket.ByteString.sendAll

udpNext :: Socket -> IO (StrictByteString, SockAddr)
udpNext socket' = Network.Socket.ByteString.recvFrom socket' packetRecvSize

udpSend :: Socket -> (StrictByteString, SockAddr) -> IO ()
udpSend socket' (data', addr') = Network.Socket.ByteString.sendAllTo socket' data' addr'

wsNext :: WS.Connection -> IO StrictByteString
wsNext = WS.receiveData

wsSend :: WS.Connection -> StrictByteString -> IO ()
wsSend conn = WS.sendBinaryData conn . B.fromStrict

quicNext :: QUIC.Stream -> IO StrictByteString
quicNext stream = QUIC.recvStream stream streamRecvChunkSize

quicSend :: QUIC.Stream -> StrictByteString -> IO ()
quicSend = QUIC.sendStream

-- | A channel is a pair of functions, one for receiving data and the other for sending data.
--
-- * @m@ is the monad in which the channel operates, usually IO or a transformer stack over IO.
-- * @nt@ and @st@ are the types of the arguments for the receiving and sending functions, respectively.
-- * @pl@ is the value produced by @nt@ and consumed by @st@.
--
-- For example, for a TCP channel, the receiving function takes a Socket and returns a ByteString,
-- while the sending function takes a Socket and a ByteString and sends the data through the socket.
--
-- See `tcpChannel` for more details.
data Channel m nt st pl = Channel {next :: nt -> m pl, send :: st -> pl -> m ()}

tlsChannel :: (MonadIO m) => Channel m TLS.Context TLS.Context StrictByteString
tlsChannel = Channel {next = tlsNext, send = tlsSend}

tcpChannel :: Channel IO Socket Socket StrictByteString
tcpChannel = Channel {next = tcpNext, send = tcpSend}

wsChannel :: Channel IO WS.Connection WS.Connection StrictByteString
wsChannel = Channel {next = wsNext, send = wsSend}

quicChannel :: Channel IO QUIC.Stream QUIC.Stream StrictByteString
quicChannel = Channel {next = quicNext, send = quicSend}

udpChannel :: Channel IO Socket Socket (StrictByteString, SockAddr)
udpChannel = Channel {next = udpNext, send = udpSend}

split :: Channel m nt st pl -> (nt -> m pl, st -> pl -> m ())
split channel = (next channel, send channel)

reunite :: (nt -> m pl) -> (st -> pl -> m ()) -> Channel m nt st pl
reunite = Channel
