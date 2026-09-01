{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Server.Protocol.Trojan.Codec (TrojanCodec, newTrojanCodec) where

import qualified Common.Codec.Socks.Address as SocksAddress
import Common.Exception (AppExceptionKind (InvariantError), throwApp)
import Common.Network.Address (Address (SockAddr), parseAddr)
import Common.Util (encodeLengthWord16be)
import Control.Monad (unless)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Control.Monad.Trans.State.Strict (get, runStateT)
import Data.Binary.Get (Get, getByteString, getWord16be, getWord8, runGetOrFail, skip)
import Data.Binary.Put (runPut)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B16
import Server.Protocol (NewCodecResult, RelayFrame (OpenTcp, TcpData, UdpData), ServerCodec (decode, encode))

crlf :: B.ByteString
crlf = "\r\n"

crlfLength :: Int
crlfLength = B.length crlf

type Key = B.ByteString

getActualKey :: Get Key
getActualKey = B16.decodeLenient <$> getByteString 56

data ParsedCodec = ParsedTcp Key Address | ParsedUdp Key

data TrojanCodec = Tcp Key | Udp Key deriving (Show)

instance ServerCodec TrojanCodec where
  encode OpenTcp {} = throwApp InvariantError "trojan codec does not encode connection frames"
  encode (TcpData msg) = return msg
  encode (UdpData content recipient) = do
    let addr = B.toStrict $ runPut $ SocksAddress.encode $ SockAddr recipient
        contentLength = encodeLengthWord16be content
    return $ addr <> contentLength <> crlf <> content

  decode msg = do
    get >>= \case
      Tcp {} -> return $ Right $ Just (B.empty, TcpData msg)
      Udp {} -> do
        case runGetOrFail decodePacket $ B.fromStrict msg of
          Left _ -> return $ Right Nothing
          Right (leftover, _, (content, addr')) -> do
            addr'' <- liftIO $ parseAddr addr'
            return $ Right $ Just (B.toStrict leftover, UdpData content addr'')
        where
          decodePacket = do
            addr <- SocksAddress.decode
            length' <- getWord16be
            skip crlfLength
            content <- getByteString (fromIntegral length')
            return (content, addr)

newTrojanCodec :: Key -> B.ByteString -> IO (NewCodecResult TrojanCodec)
newTrojanCodec expectedKey chunk = runExceptT $ do
  let res = runGetOrFail go $ B.fromStrict chunk
  case res of
    Left _ -> return Nothing
    Right (leftover, _, parsedCodec) -> do
      let msg = B.toStrict leftover
      case parsedCodec of
        ParsedTcp key addr -> do
          peerAddr <- liftIO $ parseAddr addr
          let payloads = OpenTcp peerAddr : [TcpData msg]
          return $ Just (B.empty, payloads, Tcp key)
        ParsedUdp key
          | B.null msg -> return $ Just (B.empty, [], Udp key)
          | otherwise -> do
              (decoded, codec') <- liftIO $ runStateT (decode msg) (Udp key)
              case decoded of
                Left e -> throwE e
                Right Nothing -> return $ Just (msg, [], codec')
                Right (Just (leftover', payload)) -> return $ Just (leftover', [payload], codec')
  where
    go = do
      key <- getActualKey
      unless (expectedKey == key) $ fail $ "not a valid password, actual: " ++ show key ++ ", expected: " ++ show expectedKey
      skip crlfLength
      getWord8 >>= \case
        1 -> ParsedTcp key <$> SocksAddress.decode <* skip crlfLength
        3 -> ParsedUdp key <$ SocksAddress.decode <* skip crlfLength
        commandByte -> fail $ "invalid command byte: " ++ show commandByte
