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
import Common.Exception (AppExceptionKind (ProtocolError), throwApp)
import Common.Lang.Go (fnv1a32)
import Common.Network.Address (parseAddr)
import Common.Protocol.VMess.Aead (KDFSaltConst (..))
import Common.Protocol.VMess.Aead.AuthID (match)
import Common.Protocol.VMess.Aead.KDF (kdf16, kdfN)
import Common.Protocol.VMess.Header (RequestHeader (..))
import qualified Common.Protocol.VMess.Header as Header
import qualified Common.Protocol.VMess.Header.RequestCommand as RequestCommand
import Common.Protocol.VMess.Header.RequestOption (toMask)
import qualified Common.Protocol.VMess.Header.RequestOption as RequestOption
import Common.Util (encodeLengthWord16be)
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
import Network.Socket (SockAddr)
import Server.Protocol (NewCodecResult, RelayFrame (OpenTcp, TcpData, UdpData), ServerCodec (decode, encode), relayPayload)

data VMessCodec
  = Stable RequestHeader SockAddr !Session !AeadEncoder !AeadDecoder
  | InitEncoder RequestHeader SockAddr !Session !AeadDecoder
  deriving (Show)

instance ServerCodec VMessCodec where
  encode payload = do
    get >>= \case
      InitEncoder header peerAddr session decoder -> do
        let cipherKind = Aes128Gcm
            headLengthKey = kdf16 (session ^. responseBodyKey) [value AEADRespHeaderLenKey]
        headerLengthMethod <- newCipherMethod cipherKind headLengthKey
        let nonceSize' = nonceSize cipherKind
            headerLengthNonce = kdfN (session ^. responseBodyIV) [value AEADRespHeaderLenIV] nonceSize'
            option' = toMask $ option header
            headerChunkBuffer = B.pack [session ^. responseHeader, option', 0, 0]
            headerLengthBuffer = encodeLengthWord16be headerChunkBuffer
        headerLengthCiphertext <- AeadCrypto.encrypt headerLengthMethod headerLengthNonce B.empty headerLengthBuffer
        let headerChunkKey = kdf16 (session ^. responseBodyKey) [value AEADRespHeaderPayloadKey]
        headerChunkMethod <- newCipherMethod cipherKind headerChunkKey
        let headerChunkNonce = kdfN (session ^. responseBodyIV) [value AEADRespHeaderPayloadIV] nonceSize'
        headerChunkCiphertext <- AeadCrypto.encrypt headerChunkMethod headerChunkNonce B.empty headerChunkBuffer
        let headerCiphertext = headerLengthCiphertext <> headerChunkCiphertext
        encoder <- getBodyEncoder header session
        let plaintext = relayPayload payload
        ((chunkCiphertext, session'), encoder') <- runStateT (encodePayload plaintext session) encoder
        put $ Stable header peerAddr session' encoder' decoder
        return $ headerCiphertext <> chunkCiphertext
      Stable header peerAddr session encoder decoder -> do
        let plaintext = relayPayload payload
        ((chunkCiphertext, session'), encoder') <- runStateT (encodePayload plaintext session) encoder
        put $ Stable header peerAddr session' encoder' decoder
        return chunkCiphertext

  decode ciphertext =
    get >>= \case
      InitEncoder header peerAddr session decoder -> do
        (decoded, decoder') <- liftIO $ runStateT (decodePayload ciphertext session) decoder
        case decoded of
          Nothing -> return Nothing
          Just (leftover, pending, session') -> do
            put $ InitEncoder header peerAddr session' decoder'
            case command header of
              RequestCommand.TCP -> return $ Just (leftover, TcpData pending)
              RequestCommand.UDP -> return $ Just (leftover, UdpData pending peerAddr)
              _ -> throwApp ProtocolError ("unsupported request command: " ++ show (command header))
      Stable header peerAddr session encoder decoder -> do
        (decoded, decoder') <- liftIO $ runStateT (decodePayload ciphertext session) decoder
        case decoded of
          Nothing -> return Nothing
          Just (leftover, pending, session') -> do
            put $ Stable header peerAddr session' encoder decoder'
            case command header of
              RequestCommand.TCP -> return $ Just (leftover, TcpData pending)
              RequestCommand.UDP -> return $ Just (leftover, UdpData pending peerAddr)
              _ -> throwApp ProtocolError ("unsupported request command: " ++ show (command header))

newVMessCodec :: [Key] -> StrictByteString -> IO (NewCodecResult VMessCodec)
newVMessCodec keys ciphertext = do
  opened <- decodeHeader keys ciphertext
  case opened of
    Nothing -> return Nothing
    Just (leftover, header, session) -> do
      decoder <- getBodyDecoder header session
      peerAddr <- parseAddr (address header)
      let codec = InitEncoder header peerAddr session decoder
      case command header of
        RequestCommand.TCP | B.null leftover -> return $ Just (B.empty, [OpenTcp peerAddr], codec)
        RequestCommand.TCP | otherwise -> do
          (decoded, decoder') <- runStateT (decodePayload leftover session) decoder
          case decoded of
            Nothing -> return $ Just (leftover, [OpenTcp peerAddr], codec)
            Just (leftover', pending, session') -> return $ Just (leftover', OpenTcp peerAddr : [TcpData pending], InitEncoder header peerAddr session' decoder')
        RequestCommand.UDP | B.null leftover -> return $ Just (B.empty, [], codec)
        RequestCommand.UDP | otherwise -> do
          (decoded, decoder') <- runStateT (decodePayload leftover session) decoder
          case decoded of
            Nothing -> return $ Just (leftover, [], codec)
            Just (leftover', pending, session')
              | B.null pending -> return $ Just (leftover', [], InitEncoder header peerAddr session' decoder')
              | otherwise -> return $ Just (leftover', [UdpData pending peerAddr], InitEncoder header peerAddr session' decoder')
        _ -> throwApp ProtocolError $ "unsupported VMess command: " ++ show (command header)

decodeHeader :: [Key] -> StrictByteString -> IO (Maybe (StrictByteString, RequestHeader, Session))
decodeHeader keys ciphertext
  | B.length ciphertext < 16 = return Nothing
  | otherwise = do
      let authID = B.take 16 ciphertext
      key <- match authID keys >>= maybe (throwApp ProtocolError "no matched authID") return
      opened <- AeadHeader.open key ciphertext
      case opened of
        Nothing -> return Nothing
        Just (leftover, headerPlaintext) ->
          case runGetOrFail (parseHeader key) (B.fromStrict headerPlaintext) of
            Right (_, _, (header, session, actual)) -> do
              let data' = B.take (B.length headerPlaintext - 4) headerPlaintext
                  fnv1a32' = fnv1a32 data'
              unless (actual == fnv1a32') $ do
                throwApp ProtocolError "invalid auth, but this is a AEAD request"
              return $ Just (leftover, header, session)
            Left (_, _, errorMsg) -> do
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
