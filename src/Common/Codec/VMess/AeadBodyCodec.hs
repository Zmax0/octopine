{-# LANGUAGE OverloadedStrings #-}

module Common.Codec.VMess.AeadBodyCodec (getBodyEncoder, getBodyDecoder, encodePayload, decodePayload) where

import Common.Codec.VMess.Aead (Authenticator (Authenticator), generateChacha20Poly1305Key)
import Common.Codec.VMess.AeadDecoder (AeadDecoder, DecodeResult)
import qualified Common.Codec.VMess.AeadDecoder as AeadDecoder
import Common.Codec.VMess.AeadEncoder (AeadEncoder)
import qualified Common.Codec.VMess.AeadEncoder as AeadEncoder
import Common.Codec.VMess.Session (Session (..), requestBodyIV, requestBodyKey, responseBodyIV)
import qualified Common.Codec.VMess.ShakeSizeParser as ShakeSizeParser
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (Aes128Gcm, ChaCha20Poly1305), CipherMethod, nonceSize)
import qualified Common.Crypto.Aead as Aead
import Common.Crypto.Aead.NonceGenerator (CountingNonceGenerator (..))
import Common.Protocol.VMess.Aead.KDF (kdf16)
import Common.Protocol.VMess.Header (RequestHeader (option, security))
import Common.Protocol.VMess.Header.RequestOption (RequestOption (..))
import qualified Common.Protocol.VMess.Header.SecurityType as SecurityType
import Control.Lens ((^.))
import Control.Monad.Catch (MonadThrow)
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Trans.State.Strict (StateT)
import Data.ByteString (StrictByteString)
import GHC.Stack (HasCallStack)

authLen :: [StrictByteString]
authLen = ["auth_len"]

newAuth :: CipherMethod -> Authenticator
newAuth method = Authenticator method $ CountingNonceGenerator 0 (nonceSize $ Aead.getCipherKind method)

newCipherMethod :: (MonadThrow m, HasCallStack) => CipherKind -> Key -> m CipherMethod
newCipherMethod kind key = case kind of
  ChaCha20Poly1305 -> Aead.newCipherMethod kind $ generateChacha20Poly1305Key key
  _ -> Aead.newCipherMethod kind key

getCipherKind :: RequestHeader -> CipherKind
getCipherKind header = getCipherKind_ (security header)
  where
    getCipherKind_ SecurityType.ChaCha20Poly1305 = ChaCha20Poly1305
    getCipherKind_ _ = Aes128Gcm

getBodyEncoder :: (MonadThrow m, HasCallStack) => RequestHeader -> Session -> m AeadEncoder
getBodyEncoder header session = _getBodyEncoder key iv header session
  where
    (key, iv) = case session of
      ClientSession requestBodyIV' requestBodyKey' _ _ _ -> (requestBodyKey', requestBodyIV')
      ServerSession _ _ responseBodyIV' responseBodyKey' _ -> (responseBodyKey', responseBodyIV')

_getBodyEncoder :: (MonadThrow m, HasCallStack) => Key -> StrictByteString -> RequestHeader -> Session -> m AeadEncoder
_getBodyEncoder key nonce header session = do
  let kind = getCipherKind header
  method <- newCipherMethod kind key
  let auth = newAuth method
      option' = option header
      authLength = AuthenticatedLength `elem` option'
      chunkMasking = ChunkMasking `elem` option'
      globalPadding = GlobalPadding `elem` option'
  case (authLength, chunkMasking, globalPadding) of
    (True, _, True) -> do
      let key' = kdf16 (session ^. requestBodyKey) authLen
      method' <- newCipherMethod kind key'
      let chunk = newAuth method'
          padding = ShakeSizeParser.new nonce
      pure $ AeadEncoder.AuthLengthPadding auth chunk padding
    (True, _, False) -> do
      let key' = kdf16 (session ^. requestBodyKey) authLen
      method' <- newCipherMethod kind key'
      let chunk = newAuth method'
      pure $ AeadEncoder.AuthLength auth chunk
    (False, True, False) -> do
      let padding = ShakeSizeParser.new nonce
      pure $ AeadEncoder.ShakeLength auth padding
    (False, True, True) -> do
      let padding = ShakeSizeParser.new nonce
      pure $ AeadEncoder.ShakeLengthPadding auth padding
    _ -> do
      pure $ AeadEncoder.Default auth

encodePayload :: (MonadIO m, MonadThrow m, HasCallStack) => StrictByteString -> Session -> StateT AeadEncoder m (StrictByteString, Session)
encodePayload plaintext session@ClientSession {} = AeadEncoder.encode plaintext session requestBodyIV requestBodyIV
encodePayload plaintext session@ServerSession {} = AeadEncoder.encode plaintext session requestBodyIV responseBodyIV

getBodyDecoder :: (MonadThrow m, HasCallStack) => RequestHeader -> Session -> m AeadDecoder
getBodyDecoder header session = _getBodyDecoder key iv header session
  where
    (key, iv) = case session of
      ClientSession _ _ responseBodyIV' responseBodyKey' _ -> (responseBodyKey', responseBodyIV')
      ServerSession requestBodyIV' requestBodyKey' _ _ _ -> (requestBodyKey', requestBodyIV')

_getBodyDecoder :: (MonadThrow m, HasCallStack) => Key -> StrictByteString -> RequestHeader -> Session -> m AeadDecoder
_getBodyDecoder key nonce header session = do
  let kind = getCipherKind header
      option' = option header
      authLength = AuthenticatedLength `elem` option'
      chunkMasking = ChunkMasking `elem` option'
      globalPadding = GlobalPadding `elem` option'
  method <- newCipherMethod kind key
  let auth = newAuth method
  case (authLength, chunkMasking, globalPadding) of
    (True, _, True) -> do
      let padding = ShakeSizeParser.new nonce
      method' <- newCipherMethod kind (kdf16 (session ^. requestBodyKey) authLen)
      let chunk = newAuth method'
      pure $ AeadDecoder.AuthLengthPadding auth chunk padding AeadDecoder.Padding
    (True, _, False) -> do
      method' <- newCipherMethod kind (kdf16 (session ^. requestBodyKey) authLen)
      let chunk = newAuth method'
      pure $ AeadDecoder.AuthLength auth chunk AeadDecoder.Padding
    (False, True, False) -> do
      let chunk = ShakeSizeParser.new nonce
      pure $ AeadDecoder.ShakeLength auth chunk AeadDecoder.Padding
    (False, True, True) -> do
      let padding = ShakeSizeParser.new nonce
      pure $ AeadDecoder.ShakeLengthPadding auth padding AeadDecoder.Padding
    _ -> do
      pure $ AeadDecoder.Default auth

decodePayload :: (MonadIO m, MonadThrow m, HasCallStack) => StrictByteString -> Session -> StateT AeadDecoder m DecodeResult
decodePayload ciphertext session@ClientSession {} = AeadDecoder.decode ciphertext session requestBodyIV responseBodyIV
decodePayload ciphertext session@ServerSession {} = AeadDecoder.decode ciphertext session requestBodyIV requestBodyIV
