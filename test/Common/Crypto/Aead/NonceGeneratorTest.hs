module Common.Crypto.Aead.NonceGeneratorTest (spec) where

import Common.Crypto.Aead.NonceGenerator (CountingNonceGenerator (..), generateT)
import Control.Monad.Trans.State.Strict (runState)
import qualified Data.ByteString as B
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Crypto.Aead.NonceGenerator" $ do
    it "generateT" $ do
      let nonce = B.replicate 12 0
          expected = B.pack [255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
          (generatedNonce, finalNonce, _) =
            foldl
              ( \(_, currentNonce, generator) _ ->
                  let ((generated, nextNonce), generator') = runState (generateT currentNonce) generator
                   in (generated, nextNonce, generator')
              )
              (nonce, nonce, CountingNonceGenerator 0 12)
              [1 .. 65536 :: Int]
      generatedNonce `shouldBe` expected
      finalNonce `shouldBe` expected
