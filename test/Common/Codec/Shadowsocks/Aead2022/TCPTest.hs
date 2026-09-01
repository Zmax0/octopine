{-# LANGUAGE OverloadedStrings #-}

module Common.Codec.Shadowsocks.Aead2022.TCPTest (spec) where

import Common.Codec.Shadowsocks.Aead2022.TCP (checkSaltReplay)
import Common.Protocol.Shadowsocks (Salt (Salt))
import Control.Concurrent.STM (atomically)
import qualified Data.TinyLRU as TinyLRU
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Codec.Shadowsocks.Aead2022.TCP" $ do
    it "reports a replayed salt" $ do
      saltCache <- atomically $ TinyLRU.initTinyLRU 1
      let salt = Salt "replayed-salt"
      firstCheck <- checkSaltReplay saltCache salt
      secondCheck <- checkSaltReplay saltCache salt
      [firstCheck, secondCheck] `shouldBe` [False, True]
