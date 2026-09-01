{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Server.Protocol.VMess.Codec (VMessCodec, newVMessCodec) where

import qualified Common.Codec.VMess.Address as Address
import qualified Common.Codec.VMess.Aead.Header as AeadHeader
import Common.Codec.VMess.AeadBodyCodec (decodePayload, encodePayload, getBodyDecoder, getBodyEncoder)
import Common.Codec.VMess.AeadDecoder (AeadDecoder)
import Common.Codec.VMess.AeadEncoder (AeadEncoder)
import Common.Codec.VMess.Session (Session, newServerSession, responseBodyIV, responseBodyKey, responseHeader)
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (Aes128Gcm), newCipherMethod, nonceSize)
import qualified Common.Crypto.Aead as AeadCrypto
import Common.Exception (AppException (AppException), AppExceptionKind (InvariantError, ProtocolError), throwApp)
import Common.Lang.Go (fnv1a32)
import Common.Logger (error_, loggers, trace_)
import Common.Network.Address (parseAddr)
import Common.Protocol.VMess.Aead (KDFSaltConst (..))
import Common.Protocol.VMess.Aead.AuthID (match)
import Common.Protocol.VMess.Aead.KDF (kdf16, kdfN)
import Common.Protocol.VMess.Header (RequestHeader (..))
import qualified Common.Protocol.VMess.Header as Header
import qualified Common.Protocol.VMess.Header.RequestCommand as RequestCommand
import Common.Protocol.VMess.Header.RequestOption (toMask)
import qualified Common.Protocol.VMess.Header.RequestOption as RequestOption
import Common.Util (encodeLengthWord16be, showBase64)
import Control.Exception (SomeException, toException)
import qualified Control.Exception as E
import Control.Lens ((^.))
import Control.Monad (unless)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State.Strict (get, put, runStateT)
import Data.Binary (Get, getWord8)
import Data.Binary.Get (getByteString, getWord32be, runGetOrFail, skip)
import Data.Bits (Bits ((.&.)), (.>>.))
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import qualified Data.Enum as SecurityType
import Data.Word (Word32)
import GHC.Stack (callStack)
import Network.Socket (SockAddr)
import Server.Protocol (NewCodecResult, RelayFrame (OpenTcp, TcpData, UdpData), ServerCodec (decode, encode), relayPayload)

$(loggers "s.c.VMess" ['trace_, 'error_])

data VMessCodec
  = Stable RequestHeader SockAddr !Session !AeadEncoder !AeadDecoder [StrictByteString]
  | InitDecoder [StrictByteString]
  | InitEncoder RequestHeader SockAddr !Session !AeadDecoder [StrictByteString]
  deriving (Show)

instance ServerCodec VMessCodec where
  encode payload = do
    get >>= \case
      InitEncoder header peerAddr session decoder keys -> do
        let cipherKind = Aes128Gcm
            headLengthKey = kdf16 (session ^. responseBodyKey) [value AEADRespHeaderLenKey]
            headerLengthMethod = newCipherMethod cipherKind headLengthKey
            nonceSize' = nonceSize cipherKind
            headerLengthNonce = kdfN (session ^. responseBodyIV) [value AEADRespHeaderLenIV] nonceSize'
            option' = toMask $ option header
            headerChunkBuffer = B.pack [session ^. responseHeader, option', 0, 0]
            headerLengthBuffer = encodeLengthWord16be headerChunkBuffer
            headerLengthCiphertext = AeadCrypto.encrypt headerLengthMethod headerLengthNonce B.empty headerLengthBuffer
            headerChunkKey = kdf16 (session ^. responseBodyKey) [value AEADRespHeaderPayloadKey]
            headerChunkMethod = newCipherMethod cipherKind headerChunkKey
            headerChunkNonce = kdfN (session ^. responseBodyIV) [value AEADRespHeaderPayloadIV] nonceSize'
            headerChunkCiphertext = AeadCrypto.encrypt headerChunkMethod headerChunkNonce B.empty headerChunkBuffer
            headerCiphertext = headerLengthCiphertext <> headerChunkCiphertext
            encoder = getBodyEncoder header session
            plaintext = relayPayload payload
        ((chunkCiphertext, session'), encoder') <- runStateT (encodePayload plaintext session) encoder
        put $ Stable header peerAddr session' encoder' decoder keys
        return $ headerCiphertext <> chunkCiphertext
      Stable header peerAddr session encoder decoder keys -> do
        let plaintext = relayPayload payload
        ((chunkCiphertext, session'), encoder') <- runStateT (encodePayload plaintext session) encoder
        put $ Stable header peerAddr session' encoder' decoder keys
        return chunkCiphertext
      _ -> throwApp InvariantError "vmess encoder is not initialized"

  decode ciphertext =
    get >>= \case
      InitDecoder keys -> do
        opened <- liftIO $ decodeHeader keys ciphertext
        case opened of
          Left exception -> return $ Left exception
          Right Nothing -> return $ Right Nothing
          Right (Just (leftover, header, session)) -> do
            let decoder = getBodyDecoder header session
            peerAddr <- liftIO $ parseAddr (address header)
            put $ InitEncoder header peerAddr session decoder keys
            if B.null leftover then return $ Right Nothing else decode leftover
      InitEncoder header peerAddr session decoder keys -> do
        (decoded, decoder') <- liftIO $ runStateT (decodePayload ciphertext session) decoder
        case decoded of
          Left exception -> return $ Left exception
          Right Nothing -> return $ Right Nothing
          Right (Just (leftover, pending, session')) -> do
            put $ InitEncoder header peerAddr session' decoder' keys
            return $ case command header of
              RequestCommand.TCP -> Right $ Just (leftover, TcpData pending)
              RequestCommand.UDP -> Right $ Just (leftover, UdpData pending peerAddr)
              _ -> Left $ toException $ AppException ProtocolError ("unsupported request command: " ++ show (command header)) callStack
      Stable header peerAddr session encoder decoder keys -> do
        (decoded, decoder') <- liftIO $ runStateT (decodePayload ciphertext session) decoder
        case decoded of
          Left exception -> return $ Left exception
          Right Nothing -> return $ Right Nothing
          Right (Just (leftover, pending, session')) -> do
            put $ Stable header peerAddr session' encoder decoder' keys
            return $ case command header of
              RequestCommand.TCP -> Right $ Just (leftover, TcpData pending)
              RequestCommand.UDP -> Right $ Just (leftover, UdpData pending peerAddr)
              _ -> Left $ toException $ AppException ProtocolError ("unsupported request command: " ++ show (command header)) callStack

newVMessCodec :: [Key] -> StrictByteString -> IO (NewCodecResult VMessCodec)
newVMessCodec keys ciphertext = do
  opened <- decodeHeader keys ciphertext
  case opened of
    Left exception -> return $ Left exception
    Right Nothing -> return $ Right Nothing
    Right (Just (leftover, header, session)) -> do
      let decoder = getBodyDecoder header session
      peerAddr <- parseAddr (address header)
      let codec = InitEncoder header peerAddr session decoder keys
      case command header of
        RequestCommand.TCP | B.null leftover -> return $ Right $ Just (B.empty, [OpenTcp peerAddr], codec)
        RequestCommand.TCP | otherwise -> do
          (decoded, decoder') <- runStateT (decodePayload leftover session) decoder
          case decoded of
            Left exception -> E.throwIO exception
            Right Nothing -> return $ Right $ Just (leftover, [OpenTcp peerAddr], codec)
            Right (Just (leftover', pending, session')) -> return $ Right $ Just (leftover', OpenTcp peerAddr : [TcpData pending], InitEncoder header peerAddr session' decoder' keys)
        RequestCommand.UDP | B.null leftover -> return $ Right $ Just (B.empty, [], codec)
        RequestCommand.UDP | otherwise -> do
          (decoded, decoder') <- runStateT (decodePayload leftover session) decoder
          case decoded of
            Left exception -> return $ Left exception
            Right Nothing -> return $ Right $ Just (leftover, [], codec)
            Right (Just (leftover', pending, session'))
              | B.null pending -> return $ Right $ Just (leftover', [], InitEncoder header peerAddr session' decoder' keys)
              | otherwise -> return $ Right $ Just (leftover', [UdpData pending peerAddr], InitEncoder header peerAddr session' decoder' keys)
        _ -> throwApp ProtocolError $ "unsupported VMess command: " ++ show (command header)

decodeHeader :: [Key] -> StrictByteString -> IO (Either SomeException (Maybe (StrictByteString, RequestHeader, Session)))
decodeHeader keys ciphertext
  | B.length ciphertext < 16 = return $ Right Nothing
  | otherwise = do
      let authID = B.take 16 ciphertext
      key <- match authID keys >>= maybe (throwApp ProtocolError "no matched authID") return
      _trace_ $ "matched key: " ++ showBase64 key
      opened <- AeadHeader.open key ciphertext
      case opened of
        Left exception -> return $ Left exception
        Right Nothing -> return $ Right Nothing
        Right (Just (leftover, headerPlaintext)) ->
          case runGetOrFail (parseHeader key) (B.fromStrict headerPlaintext) of
            Right (_, _, (header, session, actual)) -> do
              let data' = B.take (B.length headerPlaintext - 4) headerPlaintext
                  fnv1a32' = fnv1a32 data'
              _trace_ $ "parsed header: " ++ show header ++ ", session: " ++ show session
              unless (actual == fnv1a32') $ do
                _error_ $ "fnv1a32 data: " ++ showBase64 data' ++ ", expected: " ++ show fnv1a32' ++ ", actual: " ++ show actual
                throwApp ProtocolError "invalid auth, but this is a AEAD request"
              return $ Right $ Just (leftover, header, session)
            Left (_, _, errorMsg) -> do
              _error_ $ "failed to parse header: " ++ errorMsg
              throwApp ProtocolError $ "failed to parse header: " ++ errorMsg

parseHeader :: StrictByteString -> Get (RequestHeader, Session, Word32)
parseHeader id' = do
  version' <- getWord8
  requestBodyIV' <- getByteString 16
  requestBodyKey' <- getByteString 16
  responseHeader' <- getWord8
  option' <- getWord8
  security' <- fromIntegral <$> getWord8
  let paddingLength = security' .>>. 4
      security'' = SecurityType.toEnum $ security' .&. 0xf
  skip 1 -- fixed 0
  command' <- RequestCommand.RequestCommand <$> getWord8
  address' <- Address.decode
  skip paddingLength
  actual <- getWord32be
  let header = Header.RequestHeader version' (RequestOption.fromMask option') (Header.ID id') command' security'' address'
      session = newServerSession requestBodyIV' requestBodyKey' responseHeader'
  return (header, session, actual)
