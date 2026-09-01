{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module Server.Protocol (DecodeResult, NewCodecResult, RelayFrame (OpenTcp, TcpData, UdpData), ServerCodec (decode, encode), ServerProtocol (label, newServerCodec, newServerContext), relayPayload) where

import Common.Codec (LeftoverByteString)
import Common.Config (ServerConfig)
import Control.Exception (SomeException)
import Control.Monad.Trans.State.Strict (StateT)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Network.Socket (SockAddr)

data RelayFrame = OpenTcp SockAddr | TcpData StrictByteString | UdpData StrictByteString SockAddr deriving (Eq, Show)

relayPayload :: RelayFrame -> StrictByteString
relayPayload OpenTcp {} = B.empty
relayPayload (TcpData msg) = msg
relayPayload (UdpData msg _) = msg

type DecodeResult = Either SomeException (Maybe (LeftoverByteString, RelayFrame))

type NewCodecResult codec = Either SomeException (Maybe (LeftoverByteString, [RelayFrame], codec))

class ServerCodec codec where
  encode :: RelayFrame -> StateT codec IO StrictByteString
  decode :: StrictByteString -> StateT codec IO DecodeResult

class (ServerCodec codec, Show codec) => ServerProtocol context codec | context -> codec where
  newServerContext :: ServerConfig -> IO context
  newServerCodec :: context -> StrictByteString -> IO (NewCodecResult codec)
  label :: context -> String
