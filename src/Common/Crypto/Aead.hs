{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Common.Crypto.Aead (CipherKind (keySize, nonceSize, tagSize, Aes128Gcm, Aes256Gcm, ChaCha8Poly1305, ChaCha20Poly1305, XChaCha8Poly1305, XChaCha20Poly1305, Aead2022Blake3Aes128Gcm, Aead2022Blake3Aes256Gcm, Aead2022Blake3ChaCha8Poly1305, Aead2022Blake3ChaCha20Poly1305), CipherMethod, newCipherMethod, getCipherKind, encrypt, decrypt) where

import Common.Crypto (Ciphertext, Key, Plaintext)
import qualified Common.Crypto.ChaCha8Poly1305 as ChaCha8Poly1305
import Common.Exception (AppExceptionKind (InvariantError, ProtocolError), throwApp)
import Control.Monad.Catch (MonadThrow)
import qualified Crypto.Cipher.AES.GCM as AesGcm
import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.Cipher.ChaCha.Poly1305 as ChaCha20Poly1305
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly1305
import Crypto.Cipher.Types (AEAD (..), AEADModeImpl (..), AuthTag (AuthTag), aeadSimpleEncrypt, tryAeadSimpleDecrypt)
import Crypto.Error (CryptoFailable, onCryptoFailure)
import qualified Crypto.MAC.Poly1305 as Poly1305
import Data.Aeson (ToJSON)
import Data.Aeson.Types (FromJSON (parseJSON), ToJSON (toJSON), withText)
import Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.Text (Text, toLower)
import qualified Data.Text as T
import GHC.Stack (HasCallStack)

data CipherKind = CipherKind {keySize :: Int, nonceSize :: Int, tagSize :: Int, label :: Text}

instance Show CipherKind where
  show = T.unpack . label

pattern Aes128Gcm :: CipherKind
pattern Aes128Gcm = CipherKind 16 12 16 "aes-128-gcm"

pattern Aes256Gcm :: CipherKind
pattern Aes256Gcm = CipherKind 32 12 16 "aes-256-gcm"

pattern ChaCha8Poly1305 :: CipherKind
pattern ChaCha8Poly1305 = CipherKind 32 12 16 "chacha8-poly1305"

pattern ChaCha20Poly1305 :: CipherKind
pattern ChaCha20Poly1305 = CipherKind 32 12 16 "chacha20-poly1305"

pattern XChaCha8Poly1305 :: CipherKind
pattern XChaCha8Poly1305 = CipherKind 32 24 16 "xchacha8-poly1305"

pattern XChaCha20Poly1305 :: CipherKind
pattern XChaCha20Poly1305 = CipherKind 32 24 16 "xchacha20-poly1305"

pattern Aead2022Blake3Aes128Gcm :: CipherKind
pattern Aead2022Blake3Aes128Gcm = CipherKind 16 12 16 "2022-blake3-aes-128-gcm"

pattern Aead2022Blake3Aes256Gcm :: CipherKind
pattern Aead2022Blake3Aes256Gcm = CipherKind 32 12 16 "2022-blake3-aes-256-gcm"

pattern Aead2022Blake3ChaCha8Poly1305 :: CipherKind
pattern Aead2022Blake3ChaCha8Poly1305 = CipherKind 32 12 16 "2022-blake3-chacha8-poly1305"

pattern Aead2022Blake3ChaCha20Poly1305 :: CipherKind
pattern Aead2022Blake3ChaCha20Poly1305 = CipherKind 32 12 16 "2022-blake3-chacha20-poly1305"

instance FromJSON CipherKind where
  parseJSON = withText "CipherKind" $ \t -> case toLower t of
    "aes-128-gcm" -> return Aes128Gcm
    "aes-256-gcm" -> return Aes256Gcm
    "chacha8-poly1305" -> return ChaCha8Poly1305
    "chacha20-poly1305" -> return ChaCha20Poly1305
    "chacha20-ietf-poly1305" -> return ChaCha20Poly1305
    "xchacha8-poly1305" -> return XChaCha8Poly1305
    "xchacha20-poly1305" -> return XChaCha20Poly1305
    "2022-blake3-aes-128-gcm" -> return Aead2022Blake3Aes128Gcm
    "2022-blake3-aes-256-gcm" -> return Aead2022Blake3Aes256Gcm
    "2022-blake3-chacha8-poly1305" -> return Aead2022Blake3ChaCha8Poly1305
    "2022-blake3-chacha20-poly1305" -> return Aead2022Blake3ChaCha20Poly1305
    _ -> fail "unsupported cipher"

instance ToJSON CipherKind where
  toJSON Aes128Gcm = toJSON (label Aes128Gcm)
  toJSON Aes256Gcm = toJSON (label Aes256Gcm)
  toJSON ChaCha8Poly1305 = toJSON (label ChaCha8Poly1305)
  toJSON ChaCha20Poly1305 = toJSON (label ChaCha20Poly1305)
  toJSON XChaCha8Poly1305 = toJSON (label XChaCha8Poly1305)
  toJSON XChaCha20Poly1305 = toJSON (label XChaCha20Poly1305)
  toJSON Aead2022Blake3Aes128Gcm = toJSON (label Aead2022Blake3Aes128Gcm)
  toJSON Aead2022Blake3Aes256Gcm = toJSON (label Aead2022Blake3Aes256Gcm)
  toJSON Aead2022Blake3ChaCha8Poly1305 = toJSON (label Aead2022Blake3ChaCha8Poly1305)
  toJSON Aead2022Blake3ChaCha20Poly1305 = toJSON (label Aead2022Blake3ChaCha20Poly1305)
  toJSON CipherKind {} = toJSON (label Aes128Gcm)

data CipherMethod where
  AesGcmMethod :: !AesGcm.Context -> CipherKind -> CipherMethod
  ChaCha8Poly1305Method :: (ByteArrayAccess ba) => ba -> CipherKind -> CipherMethod
  ChaCha20Poly1305Method :: !ChaCha20Poly1305.Context -> CipherKind -> CipherMethod
  XChaCha8Poly1305Method :: (ByteArrayAccess ba) => ba -> CipherKind -> CipherMethod
  XChaCha20Poly1305Method :: !ChaChaPoly1305.Key -> CipherKind -> CipherMethod

instance Show CipherMethod where
  show (AesGcmMethod _ k) =
    "BlockCipherMethod (AES" ++ show (keySize k * 8) ++ "), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)
  show (ChaCha8Poly1305Method _ k) =
    "BlockCipherMethod (chacha8poly1305), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)
  show (ChaCha20Poly1305Method _ k) =
    "BlockCipherMethod (chacha20poly1305), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)
  show (XChaCha8Poly1305Method _ k) =
    "BlockCipherMethod (xchacha8poly1305), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)
  show (XChaCha20Poly1305Method _ k) =
    "BlockCipherMethod (xchacha20poly1305), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)

newCipherMethod :: (MonadThrow m, HasCallStack) => CipherKind -> Key -> m CipherMethod
newCipherMethod Aes128Gcm key = newAesGcmCipher Aes128Gcm key
newCipherMethod Aead2022Blake3Aes128Gcm key = newAesGcmCipher Aead2022Blake3Aes128Gcm key
newCipherMethod Aes256Gcm key = newAesGcmCipher Aes256Gcm key
newCipherMethod Aead2022Blake3Aes256Gcm key = newAesGcmCipher Aead2022Blake3Aes256Gcm key
newCipherMethod ChaCha8Poly1305 key = do
  pure $ ChaCha8Poly1305Method key ChaCha8Poly1305
newCipherMethod Aead2022Blake3ChaCha8Poly1305 key = do
  pure $ ChaCha8Poly1305Method key Aead2022Blake3ChaCha8Poly1305
newCipherMethod ChaCha20Poly1305 key = do
  cipher <- cryptoOrThrow InvariantError "initialize ChaCha20-Poly1305" $ ChaCha20Poly1305.newContext key
  pure $ ChaCha20Poly1305Method cipher ChaCha20Poly1305
newCipherMethod XChaCha8Poly1305 key = do
  pure $ XChaCha8Poly1305Method key XChaCha8Poly1305
newCipherMethod Aead2022Blake3ChaCha20Poly1305 key = do
  cipher <- cryptoOrThrow InvariantError "initialize ChaCha20-Poly1305" $ ChaCha20Poly1305.newContext key
  pure $ ChaCha20Poly1305Method cipher Aead2022Blake3ChaCha20Poly1305
newCipherMethod XChaCha20Poly1305 key = do
  cipher <- cryptoOrThrow InvariantError "initialize XChaCha20 key" $ ChaChaPoly1305.key key
  pure $ XChaCha20Poly1305Method cipher XChaCha20Poly1305
newCipherMethod _ _ = throwApp InvariantError "initialize unsupported cipher"

newAesGcmCipher :: (MonadThrow m, HasCallStack) => CipherKind -> Key -> m CipherMethod
newAesGcmCipher kind key
  | B.length key /= keySize kind = throwApp InvariantError $ "initialize " ++ show kind ++ ": invalid key length, expected=" ++ show (keySize kind) ++ ", actual=" ++ show (B.length key)
  | otherwise = do
      context <- cryptoOrThrow InvariantError "initialize AES-GCM" $ AesGcm.newContext key
      pure $ AesGcmMethod context kind

getCipherKind :: CipherMethod -> CipherKind
getCipherKind (AesGcmMethod _ kind) = kind
getCipherKind (ChaCha8Poly1305Method _ kind) = kind
getCipherKind (ChaCha20Poly1305Method _ kind) = kind
getCipherKind (XChaCha8Poly1305Method _ kind) = kind
getCipherKind (XChaCha20Poly1305Method _ kind) = kind

type AAD = B.ByteString

encrypt :: (MonadThrow m, HasCallStack, ByteArrayAccess nonce) => CipherMethod -> nonce -> AAD -> Plaintext -> m Ciphertext
encrypt (AesGcmMethod context kind) nonce aad plaintext =
  pure $ AesGcm.encrypt context nonce aad plaintext $ tagSize kind
encrypt (ChaCha8Poly1305Method key kind) nonce aad plaintext = do
  aead <- aeadChaCha8Poly1305Init $ ChaCha.initialize 8 key nonce
  pure $ encrypt' aead aad plaintext $ tagSize kind
encrypt (ChaCha20Poly1305Method context kind) nonce aad plaintext =
  cryptoOrThrow InvariantError "encrypt ChaCha20-Poly1305" $ ChaCha20Poly1305.encrypt context nonce aad plaintext $ tagSize kind
encrypt (XChaCha8Poly1305Method key kind) nonce aad plaintext = do
  aead <- aeadChaCha8Poly1305Init $ ChaCha.initializeX 8 key nonce
  pure $ encrypt' aead aad plaintext $ tagSize kind
encrypt (XChaCha20Poly1305Method key_ kind) nonce aad plaintext = do
  aead <- cryptoOrThrow InvariantError "initialize XChaCha20 nonce" $ aeadXchacha20poly1305Init key_ nonce
  pure $ encrypt' aead aad plaintext $ tagSize kind

type TagSize = Int

encrypt' :: AEAD cipher -> AAD -> Plaintext -> TagSize -> Ciphertext
encrypt' aead aad plaintext tagSize' = do
  let (tag, encrypted) = aeadSimpleEncrypt aead aad plaintext tagSize'
  encrypted <> BA.convert tag

decrypt :: (MonadThrow m, HasCallStack, ByteArrayAccess nonce) => CipherMethod -> nonce -> AAD -> Ciphertext -> m Plaintext
decrypt (AesGcmMethod context kind) nonce aad ciphertext =
  authenticated $ AesGcm.decrypt context nonce aad ciphertext $ tagSize kind
decrypt (ChaCha8Poly1305Method key kind) nonce aad ciphertext = do
  aead <- aeadChaCha8Poly1305Init $ ChaCha.initialize 8 key nonce
  decrypt' aead aad ciphertext $ tagSize kind
decrypt (ChaCha20Poly1305Method context kind) nonce aad ciphertext =
  authenticated $ ChaCha20Poly1305.decrypt context nonce aad ciphertext $ tagSize kind
decrypt (XChaCha8Poly1305Method key kind) nonce aad ciphertext = do
  aead <- aeadChaCha8Poly1305Init $ ChaCha.initializeX 8 key nonce
  decrypt' aead aad ciphertext $ tagSize kind
decrypt (XChaCha20Poly1305Method key' kind) nonce aad ciphertext = do
  aead <- cryptoOrThrow InvariantError "initialize XChaCha20 nonce" $ aeadXchacha20poly1305Init key' nonce
  decrypt' aead aad ciphertext $ tagSize kind

decrypt' :: (MonadThrow m, HasCallStack) => AEAD cipher -> AAD -> Ciphertext -> TagSize -> m Plaintext
decrypt' aead aad ciphertext tagSize' = do
  let length' = B.length ciphertext - tagSize'
      (ciphertext', tag) = B.splitAt length' ciphertext
      tag' = AuthTag $ BA.convert tag
      decrypted = authenticated $ tryAeadSimpleDecrypt aead aad ciphertext' tagSize' tag'
  decrypted

authenticated :: (MonadThrow m, HasCallStack) => Maybe Plaintext -> m Plaintext
authenticated = maybe (throwApp ProtocolError "AEAD authentication failed") pure

aeadXchacha20poly1305Init :: (ByteArrayAccess nonce) => ChaChaPoly1305.Key -> nonce -> CryptoFailable (AEAD ChaChaPoly1305.State)
aeadXchacha20poly1305Init key nonce = do
  aeadState' <- ChaChaPoly1305.initializeX key <$> ChaChaPoly1305.nonce24 nonce
  return $ AEAD model aeadState'
  where
    model =
      AEADModeImpl
        { aeadImplAppendHeader = \st aad -> ChaChaPoly1305.finalizeAAD $ ChaChaPoly1305.appendAAD aad st,
          aeadImplEncrypt = flip ChaChaPoly1305.encrypt,
          aeadImplDecrypt = flip ChaChaPoly1305.decrypt,
          aeadImplFinalize = \st _ -> let Poly1305.Auth tag = ChaChaPoly1305.finalize st in AuthTag tag
        }

aeadChaCha8Poly1305Init :: (MonadThrow m, HasCallStack) => ChaCha.State -> m (AEAD ChaCha8Poly1305.State)
aeadChaCha8Poly1305Init rootState = do
  key <- cryptoOrThrow InvariantError "initialize Poly1305 key" $ Poly1305.key $ B.take 32 polyKey
  let initialState = ChaCha8Poly1305.State encryptionState (Poly1305.initialize key) 0 0
  pure $ AEAD model initialState
  where
    (polyKey, encryptionState) = ChaCha.generate rootState 64 :: (B.ByteString, ChaCha.State)
    model =
      AEADModeImpl
        { aeadImplAppendHeader = \state aad -> ChaCha8Poly1305.finalizeAAD $ ChaCha8Poly1305.appendAAD aad state,
          aeadImplEncrypt = ChaCha8Poly1305.encrypt,
          aeadImplDecrypt = ChaCha8Poly1305.decrypt,
          aeadImplFinalize = \state _ -> let Poly1305.Auth tag = ChaCha8Poly1305.finalize state in AuthTag tag
        }

cryptoOrThrow :: (MonadThrow m, HasCallStack) => AppExceptionKind -> String -> CryptoFailable a -> m a
cryptoOrThrow kind operation = onCryptoFailure (\err -> throwApp kind (operation ++ ": " ++ show err)) pure
