module Common.Codec.Socks.AddressTest (spec) where

import Common.Codec.Socks.Address (decode)
import Data.Binary.Get (runGet)
import qualified Data.ByteString as B
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Codec.Socks.Address" $ do
    it "decode" $ do
      let bytes = B.pack [1, 192, 168, 89, 9, 227, 119]
      show (runGet decode (B.fromStrict bytes)) `shouldBe` "192.168.89.9:58231"

      let bytes' = B.pack [3, 15, 119, 119, 119, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0, 80]
      show (runGet decode (B.fromStrict bytes')) `shouldBe` "www.example.com:80"

      let bytes'' = B.pack [4, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 233, 123]
      show (runGet decode (B.fromStrict bytes'')) `shouldBe` "[abcd:ef01:2345:6789:abcd:ef01:2345:6789]:59771"
