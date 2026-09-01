{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Common.Crypto.Aead (CipherKind (keySize, nonceSize, tagSize, Aes128Gcm, Aes256Gcm, ChaCha8Poly1305, ChaCha20Poly1305, XChaCha8Poly1305, XChaCha20Poly1305, Aead2022Blake3Aes128Gcm, Aead2022Blake3Aes256Gcm, Aead2022Blake3ChaCha8Poly1305, Aead2022Blake3ChaCha20Poly1305), CipherMethod, newCipherMethod, getCipherKind, encrypt, decrypt) where

import Common.Crypto (Ciphertext, Key, Plaintext)
import qualified Common.Crypto.ChaCha8Poly1305 as ChaCha8Poly1305
import Crypto.Cipher.AES (AES128, AES256)
import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly1305
import Crypto.Cipher.Types (AEAD (..), AEADMode (AEAD_GCM), AEADModeImpl (..), AuthTag (AuthTag), BlockCipher (aeadInit), Cipher (cipherName), aeadSimpleDecrypt, aeadSimpleEncrypt, cipherInit)
import Crypto.Error (CryptoFailable, throwCryptoError)
import qualified Crypto.MAC.Poly1305 as Poly1305
import Data.Aeson (ToJSON)
import Data.Aeson.Types (FromJSON (parseJSON), ToJSON (toJSON), withText)
import Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.Maybe (fromMaybe)
import Data.Text (Text, toLower)
import qualified Data.Text as T

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
pattern Aead2022Blake3ChaCha20Poly1305 = CipherKind 32 24 16 "2022-blake3-chacha20-poly1305"

instance FromJSON CipherKind where
  parseJSON = withText "CipherKind" $ \t -> case toLower t of
    "aes-128-gcm" -> return Aes128Gcm
    "aes-256-gcm" -> return Aes256Gcm
    "chacha20-poly1305" -> return ChaCha20Poly1305
    "chacha20-ietf-poly1305" -> return ChaCha20Poly1305
    "xchacha8-poly1305" -> return XChaCha8Poly1305
    "xchacha20-poly1305" -> return XChaCha20Poly1305
    "2022-blake3-aes-128-gcm" -> return Aead2022Blake3Aes128Gcm
    "2022-blake3-aes-256-gcm" -> return Aead2022Blake3Aes256Gcm
    "2022-blake3-chacha8-poly1305" -> return Aead2022Blake3ChaCha8Poly1305
    "2022-blake3-chacha20-poly1305" -> return Aead2022Blake3ChaCha20Poly1305
    _ -> return Aes128Gcm

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
  BlockCipherMethod :: (BlockCipher c) => c -> CipherKind -> CipherMethod
  ChaCha8Poly1305Method :: (ByteArrayAccess ba) => ba -> CipherKind -> CipherMethod
  ChaCha20Poly1305Method :: (ByteArrayAccess ba) => ba -> CipherKind -> CipherMethod
  XChaCha8Poly1305Method :: (ByteArrayAccess ba) => ba -> CipherKind -> CipherMethod
  XChaCha20Poly1305Method :: (ByteArrayAccess ba) => ba -> CipherKind -> CipherMethod

instance Show CipherMethod where
  show (BlockCipherMethod c k) =
    "BlockCipherMethod (" ++ cipherName c ++ "), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)
  show (ChaCha8Poly1305Method _ k) =
    "BlockCipherMethod (chacha8poly1305), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)
  show (ChaCha20Poly1305Method _ k) =
    "BlockCipherMethod (chacha20poly1305), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)
  show (XChaCha8Poly1305Method _ k) =
    "BlockCipherMethod (xchacha8poly1305), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)
  show (XChaCha20Poly1305Method _ k) =
    "BlockCipherMethod (xchacha20poly1305), NonceSize=" ++ show (nonceSize k) ++ ", TagSize=" ++ show (tagSize k)

newCipherMethod :: CipherKind -> Key -> CipherMethod
newCipherMethod Aes128Gcm key = do
  let cipher = throwCryptoError (cipherInit key :: CryptoFailable AES128)
  BlockCipherMethod cipher Aes128Gcm
newCipherMethod Aead2022Blake3Aes128Gcm key = do
  let cipher = throwCryptoError (cipherInit (B.take 16 key) :: CryptoFailable AES128)
  BlockCipherMethod cipher Aead2022Blake3Aes128Gcm
newCipherMethod Aes256Gcm key = do
  let cipher = throwCryptoError (cipherInit key :: CryptoFailable AES256)
  BlockCipherMethod cipher Aes256Gcm
newCipherMethod Aead2022Blake3Aes256Gcm key = do
  let cipher = throwCryptoError (cipherInit key :: CryptoFailable AES256)
  BlockCipherMethod cipher Aead2022Blake3Aes256Gcm
newCipherMethod ChaCha8Poly1305 key = do
  ChaCha8Poly1305Method key ChaCha8Poly1305
newCipherMethod Aead2022Blake3ChaCha8Poly1305 key = do
  ChaCha8Poly1305Method key Aead2022Blake3ChaCha8Poly1305
newCipherMethod ChaCha20Poly1305 key = do
  ChaCha20Poly1305Method key ChaCha20Poly1305
newCipherMethod XChaCha8Poly1305 key = do
  XChaCha8Poly1305Method key XChaCha8Poly1305
newCipherMethod Aead2022Blake3ChaCha20Poly1305 key = do
  ChaCha20Poly1305Method key Aead2022Blake3ChaCha20Poly1305
newCipherMethod XChaCha20Poly1305 key = do
  XChaCha20Poly1305Method key XChaCha20Poly1305
newCipherMethod _ _ = error "unsupported"

getCipherKind :: CipherMethod -> CipherKind
getCipherKind (BlockCipherMethod _ kind) = kind
getCipherKind (ChaCha8Poly1305Method _ kind) = kind
getCipherKind (ChaCha20Poly1305Method _ kind) = kind
getCipherKind (XChaCha8Poly1305Method _ kind) = kind
getCipherKind (XChaCha20Poly1305Method _ kind) = kind

type AAD = B.ByteString

encrypt :: (ByteArrayAccess nonce) => CipherMethod -> nonce -> AAD -> Plaintext -> Ciphertext
encrypt (BlockCipherMethod cipher kind) nonce aad plaintext = do
  let aead = throwCryptoError $ aeadInit AEAD_GCM cipher nonce
  encrypt' aead aad plaintext $ tagSize kind
encrypt (ChaCha8Poly1305Method key kind) nonce aad plaintext = do
  let aead = aeadChaCha8Poly1305Init key nonce
  encrypt' aead aad plaintext $ tagSize kind
encrypt (ChaCha20Poly1305Method key_ kind) nonce aad plaintext = do
  let aead = throwCryptoError $ ChaChaPoly1305.aeadChacha20poly1305Init key_ nonce
  encrypt' aead aad plaintext $ tagSize kind
encrypt (XChaCha8Poly1305Method key kind) nonce aad plaintext = do
  let aead = aeadXchacha8poly1305Init key nonce
  encrypt' aead aad plaintext $ tagSize kind
encrypt (XChaCha20Poly1305Method key_ kind) nonce aad plaintext = do
  let aead = throwCryptoError $ aeadXchacha20poly1305Init key_ nonce
  encrypt' aead aad plaintext $ tagSize kind

type TagSize = Int

encrypt' :: AEAD cipher -> AAD -> Plaintext -> TagSize -> Ciphertext
encrypt' aead aad plaintext tagSize' = do
  let (tag, encrypted) = aeadSimpleEncrypt aead aad plaintext tagSize'
  encrypted <> BA.convert tag

decrypt :: (ByteArrayAccess nonce) => CipherMethod -> nonce -> AAD -> Ciphertext -> Plaintext
decrypt (BlockCipherMethod cipher kind) nonce aad ciphertext = do
  let aead = throwCryptoError $ aeadInit AEAD_GCM cipher nonce
  decrypt' aead aad ciphertext $ tagSize kind
decrypt (ChaCha8Poly1305Method key kind) nonce aad ciphertext = do
  let aead = aeadChaCha8Poly1305Init key nonce
  decrypt' aead aad ciphertext $ tagSize kind
decrypt (ChaCha20Poly1305Method key' kind) nonce aad ciphertext = do
  let aead = throwCryptoError $ ChaChaPoly1305.aeadChacha20poly1305Init key' nonce
  decrypt' aead aad ciphertext $ tagSize kind
decrypt (XChaCha8Poly1305Method key kind) nonce aad ciphertext = do
  let aead = aeadXchacha8poly1305Init key nonce
  decrypt' aead aad ciphertext $ tagSize kind
decrypt (XChaCha20Poly1305Method key' kind) nonce aad ciphertext = do
  let aead = throwCryptoError $ aeadXchacha20poly1305Init key' nonce
  decrypt' aead aad ciphertext $ tagSize kind

decrypt' :: AEAD cipher -> AAD -> Ciphertext -> TagSize -> Plaintext
decrypt' aead aad ciphertext tagSize' = do
  let length' = B.length ciphertext - tagSize'
      (ciphertext', tag) = B.splitAt length' ciphertext
      tag' = AuthTag $ BA.convert tag
      decrypted = fromMaybe (error "aead error") $ aeadSimpleDecrypt aead aad ciphertext' tag'
  decrypted

aeadXchacha8poly1305Init :: (ByteArrayAccess key, ByteArrayAccess nonce) => key -> nonce -> AEAD ChaCha8Poly1305.State
aeadXchacha8poly1305Init key nonce = AEAD model initialState
  where
    rootState = ChaCha.initializeX 8 key nonce
    (polyKey, encryptionState) = ChaCha.generate rootState 64 :: (B.ByteString, ChaCha.State)
    initialState = ChaCha8Poly1305.State encryptionState (throwCryptoError $ Poly1305.initialize $ B.take 32 polyKey) 0 0
    model =
      AEADModeImpl
        { aeadImplAppendHeader = \state aad -> ChaCha8Poly1305.finalizeAAD $ ChaCha8Poly1305.appendAAD aad state,
          aeadImplEncrypt = ChaCha8Poly1305.encrypt,
          aeadImplDecrypt = ChaCha8Poly1305.decrypt,
          aeadImplFinalize = \state _ -> let Poly1305.Auth tag = ChaCha8Poly1305.finalize state in AuthTag tag
        }

aeadXchacha20poly1305Init :: (ByteArrayAccess k, ByteArrayAccess n) => k -> n -> CryptoFailable (AEAD ChaChaPoly1305.State)
aeadXchacha20poly1305Init key nonce = do
  aeadState' <- ChaChaPoly1305.nonce24 nonce >>= ChaChaPoly1305.initializeX key
  return $ AEAD model aeadState'
  where
    model =
      AEADModeImpl
        { aeadImplAppendHeader = \st aad -> ChaChaPoly1305.finalizeAAD $ ChaChaPoly1305.appendAAD aad st,
          aeadImplEncrypt = flip ChaChaPoly1305.encrypt,
          aeadImplDecrypt = flip ChaChaPoly1305.decrypt,
          aeadImplFinalize = \st _ -> let Poly1305.Auth tag = ChaChaPoly1305.finalize st in AuthTag tag
        }

aeadChaCha8Poly1305Init :: (ByteArrayAccess key, ByteArrayAccess nonce) => key -> nonce -> AEAD ChaCha8Poly1305.State
aeadChaCha8Poly1305Init key nonce = AEAD model initialState
  where
    rootState = ChaCha.initialize 8 key nonce
    (polyKey, encryptionState) = ChaCha.generate rootState 64 :: (B.ByteString, ChaCha.State)
    initialState = ChaCha8Poly1305.State encryptionState (throwCryptoError $ Poly1305.initialize $ B.take 32 polyKey) 0 0
    model =
      AEADModeImpl
        { aeadImplAppendHeader = \state aad -> ChaCha8Poly1305.finalizeAAD $ ChaCha8Poly1305.appendAAD aad state,
          aeadImplEncrypt = ChaCha8Poly1305.encrypt,
          aeadImplDecrypt = ChaCha8Poly1305.decrypt,
          aeadImplFinalize = \state _ -> let Poly1305.Auth tag = ChaCha8Poly1305.finalize state in AuthTag tag
        }
