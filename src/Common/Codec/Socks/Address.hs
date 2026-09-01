{-# LANGUAGE LambdaCase #-}

module Common.Codec.Socks.Address (decode, encode, requireLength) where

import Common.Network.Address (Address (SockAddr))
import qualified Common.Network.Address as Network
import qualified Common.Protocol.Socks as Socks
import Data.Binary (Put, putWord8)
import Data.Binary.Get (Get, getByteString, getWord16be, getWord8, runGet, skip)
import Data.Binary.Put (putByteString, putWord16be, putWord32be)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Network.Socket (SockAddr (SockAddrInet, SockAddrInet6), hostAddressToTuple, tupleToHostAddress, tupleToHostAddress6)

decode :: Get Address
decode = do
  getWord8 >>= \case
    1 -> do
      host <- tupleToHostAddress <$> ((,,,) <$> getWord8 <*> getWord8 <*> getWord8 <*> getWord8)
      SockAddr . (`SockAddrInet` host) . fromIntegral <$> getWord16be
    4 -> do
      host <- tupleToHostAddress6 <$> ((,,,,,,,) <$> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be)
      SockAddr . (\port -> SockAddrInet6 port 0 host 0) . fromIntegral <$> getWord16be
    3 -> Network.Domain . decodeUtf8 <$> (getByteString . fromIntegral =<< getWord8) <*> getWord16be
    other -> fail $ "unknown socks address type: " ++ show other

encode :: Address -> Put
encode (Network.Domain host port) = putWord8 (fromIntegral $ fromEnum Socks.Domain) <> putWord8 (fromIntegral $ T.length host) <> putByteString (encodeUtf8 host) <> putWord16be port
encode (SockAddr (SockAddrInet port host)) =
  let (a, b, c, d) = hostAddressToTuple host
   in putWord8 (fromIntegral $ fromEnum Socks.Ipv4) <> putWord8 a <> putWord8 b <> putWord8 c <> putWord8 d <> putWord16be (fromIntegral port)
encode (SockAddr (SockAddrInet6 port _ (ip0, ip1, ip2, ip3) _)) = putWord8 (fromIntegral $ fromEnum Socks.Ipv6) <> putWord32be ip0 <> putWord32be ip1 <> putWord32be ip2 <> putWord32be ip3 <> putWord16be (fromIntegral port)
encode _ = error "unsupported socket address"

requireLength :: BL.ByteString -> Int -> Int
requireLength msg index = runGet getLength msg
  where
    getLength = do
      skip index
      (toEnum . fromIntegral <$> getWord8 :: Get Socks.AddressType) >>= \case
        Socks.Ipv4 -> return 7
        Socks.Ipv6 -> return 19
        Socks.Domain -> (\length' -> 3 + fromIntegral length') <$> getWord8
