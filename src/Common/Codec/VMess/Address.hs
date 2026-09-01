{-# LANGUAGE LambdaCase #-}

module Common.Codec.VMess.Address (decode) where

import Common.Network.Address (Address (..))
import Data.Binary (Get, getWord8)
import Data.Binary.Get (getByteString, getWord16be)
import Data.Text.Encoding (decodeUtf8)
import Network.Socket (SockAddr (SockAddrInet, SockAddrInet6), tupleToHostAddress, tupleToHostAddress6)

decode :: Get Address
decode = do
  port <- getWord16be
  getWord8 >>= \case
    1 -> do
      ipv4 <- tupleToHostAddress <$> ((,,,) <$> getWord8 <*> getWord8 <*> getWord8 <*> getWord8)
      return $ SockAddr $ SockAddrInet (fromIntegral port) ipv4
    2 -> do
      length' <- fromIntegral <$> getWord8
      host <- decodeUtf8 <$> getByteString length'
      return $ Domain host port
    3 -> do
      ipv6 <- tupleToHostAddress6 <$> ((,,,,,,,) <$> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be)
      return $ SockAddr $ SockAddrInet6 (fromIntegral port) 0 ipv6 0
    other -> fail $ "unknown VMess address type: " ++ show other
