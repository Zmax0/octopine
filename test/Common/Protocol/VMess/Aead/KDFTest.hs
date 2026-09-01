{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol.VMess.Aead.KDFTest (spec) where

import Common.Protocol.VMess.Aead.KDF (kdf)
import qualified Data.ByteString.Base16 as Base16
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Protocol.VMess.Aead.KDF" $ do
    it "kdf" $ do
      let key = "Demo Key for KDF Value Test"
          path =
            [ "Demo Path for KDF Value Test",
              "Demo Path for KDF Value Test2",
              "Demo Path for KDF Value Test3"
            ]
      Base16.encode (kdf key path) `shouldBe` "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"
