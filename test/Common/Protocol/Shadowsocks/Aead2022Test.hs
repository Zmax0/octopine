{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol.Shadowsocks.Aead2022Test (spec) where

import Common.Codec.Shadowsocks.Aead (newAuthenticator)
import Common.Codec.Shadowsocks.Aead2022.TCP (initDecoder, newHeader, withEih)
import qualified Common.Codec.Shadowsocks.Identity as Identity
import qualified Common.Codec.Shadowsocks.TCP.Session as Session
import qualified Common.Codec.Socks.Address as Address
import Common.Crypto.Aead (CipherKind (Aead2022Blake3Aes128Gcm, Aead2022Blake3Aes256Gcm, keySize))
import Common.Dice (rollBytes)
import Common.Network.Address (Address (Domain))
import Common.Protocol.Shadowsocks (Mode (Client, Server), Salt (Salt))
import Common.Protocol.Shadowsocks.Aead2022 (passwordToKeys, sessionSubKey)
import Common.Protocol.Shadowsocks.User (ServerUserManager (ServerUserManager))
import Common.Util (encodeWord16BE, showBase64)
import Control.Concurrent.STM (atomically)
import Control.Lens ((^.))
import Control.Monad.Trans.State.Strict (runStateT)
import Data.Binary.Put (runPut)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import Data.List (uncons)
import Data.Maybe (fromJust)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8)
import qualified Data.TinyLRU as TinyLRU
import qualified StmContainers.Map as STMMap
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Protocol.Shadowsocks.Aead2022" $ do
    it "sessionSubKey" $ do
      key <- either fail pure $ B64.decode "Lc3tTx0BY6ZJ/fCwOx3JvF0I/anhwJBO5p2+FA5Vce4="
      salt <- Salt <$> either fail pure (B64.decode "3oFO0VyLyGI4nFN0M9P+62vPND/L6v8IingaPJWTbJA=")
      B64.encode (sessionSubKey key salt) `shouldBe` "EdNE+4U8dVnHT0+poAFDK2bdlwfrHT61sUNr9WYPh+E="
    it "tcpWithEih" $ do
      let ipsk = "leWhlhIIhjHhGeaGVpqpRA=="
          upsk = "BomScdlR6tXdKxm4FyZg9g=="
          password = ipsk ++ ":" ++ upsk
      (key, identityKeys) <- passwordToKeys $ T.pack password
      (showBase64 . fst . fromJust . uncons $ identityKeys) `shouldBe` ipsk
      showBase64 key `shouldBe` upsk
      salt <- Salt <$> either fail pure (B64.decode "/xyg1YnI2gNuMydqgt8MgbfT0zDMougbi64SbDsVn1Q=")
      let eih = withEih Aead2022Blake3Aes256Gcm key identityKeys salt
      B64.encode eih `shouldBe` "jGIxVuv1qqwcBYak0kGGaA=="
    it "tcp" $ do
      testTcp Aead2022Blake3Aes128Gcm
      testTcp Aead2022Blake3Aes256Gcm

testTcp :: CipherKind -> IO ()
testTcp cipher = do
  passwordBytes <- rollBytes $ keySize cipher
  let password = decodeUtf8 $ B64.encode passwordBytes
  (key, _) <- passwordToKeys password
  identity <- Identity.newIdentity cipher
  let salt@(Salt saltBytes) = identity ^. Identity.salt
      session = Session.Session Server Nothing identity
      authenticator = newAuthenticator cipher $ sessionSubKey key salt
  payload <- rollBytes 1
  let request = B.toStrict (runPut $ Address.encode $ Domain "localhost" 80) <> encodeWord16BE 0 <> payload
  ((fixed, variable, leftover), _) <- runStateT (newHeader Client Nothing request) authenticator
  leftover `shouldBe` B.empty

  let ciphertext = saltBytes <> fixed <> variable
  saltCache <- atomically $ TinyLRU.initTinyLRU 1
  userManager <- atomically $ ServerUserManager <$> STMMap.new
  (Just (leftover', plaintext, _), _) <- runStateT (initDecoder cipher key False saltCache userManager ciphertext) session
  leftover' `shouldBe` B.empty
  plaintext `shouldBe` payload
