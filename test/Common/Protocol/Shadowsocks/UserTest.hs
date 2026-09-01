{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol.Shadowsocks.UserTest (spec) where

import Common.Protocol.Shadowsocks.User (newServerUser)
import qualified Data.ByteString.Base64 as B64
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Protocol.Shadowsocks.User" $ do
    it "newServerUser" $ do
      key <- either fail pure $ B64.decode "4w0GKJ9U3Ox7CIXGU4A3LDQAqP6qrp/tUi/ilpOR9p4="
      let user1 = newServerUser "username" key
          user2 = newServerUser "username" key
      show user1 `shouldBe` "N:username, K:4w0GKJ9U3Ox7CIXGU4A3LDQAqP6qrp/tUi/ilpOR9p4=, IH:b\"Q\\xff\\xfa\\x00\\x08:\\xafx\\xcd\\xf5\\xb3\\xf2[\\xb8\\x0c\\xab\""
      user1 `shouldBe` user2
