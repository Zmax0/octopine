{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol.VMess.IDTest (spec) where

import Common.Protocol.VMess.ID (newAlterIDs, newID, nextID)
import qualified Data.ByteString.Base64 as B64
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Protocol.VMess.ID" $ do
    it "newID" $ do
      let id' = B64.encode $ newID ("b831381d-6324-4d53-ad4f-8cda48b30811" :: String)
      id' `shouldBe` "tQ2RasDOwGeYGvjl84p1jw=="

      let id'' = B64.encode $ nextID $ newID ("b831381d-6324-4d53-ad4f-8cda48b30811" :: String)
      id'' `shouldBe` "M042vDoMqPkmEB1F6Gwujg=="

    it "newAlterIDs" $ do
      let id' = newID ("b831381d-6324-4d53-ad4f-8cda48b30811" :: String)
          alterIDs = newAlterIDs id' 64
      B64.encode (last alterIDs) `shouldBe` "bj/9x1+roVhMqHxY6MS6yg=="
