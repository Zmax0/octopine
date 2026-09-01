{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol.VMess.Aead.AuthIDTest (spec) where

import Common.Protocol.VMess (now)
import Common.Protocol.VMess.Aead.AuthID (createAuthID, match)
import Common.Protocol.VMess.Aead.KDF (kdf16)
import Test.Hspec (Spec, describe, it, shouldReturn)

spec :: Spec
spec =
  describe "Common.Protocol.VMess.Aead.AuthID" $ do
    it "match" $ do
      let key = kdf16 "Demo Key for Auth ID Test" ["Demo Path for Auth ID Test"]
          wrongKey = kdf16 "Demo Key for Auth ID Test2" ["Demo Path for Auth ID Test"]
      authId <- createAuthID key =<< now
      match authId [wrongKey] `shouldReturn` Nothing

      let key' = kdf16 "Demo Key for Auth ID Test" ["Demo Path for Auth ID Test"]
          wrongKey' = kdf16 "Demo Key for Auth ID Test2" ["Demo Path for Auth ID Test"]
      authId' <- createAuthID key' =<< now
      match authId' [wrongKey', key'] `shouldReturn` Just key'
