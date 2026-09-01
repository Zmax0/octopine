{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}

module Common.Codec.VMess.AeadTest (spec) where

import Common.Codec.VMess.Aead (generateChacha20Poly1305Key)
import Common.Util (showBase64)
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Codec.VMess.Aead" $ do
    it "generateChacha20Poly1305Key" $ do
      let bytes = "fn bubble_sort<T: Ord>(arr: &mut [T]) {let mut swapped = true;while swapped {swapped = false;for i in 1..arr.len() {if arr[i - 1] > arr[i] {arr.swap(i - 1, i);swapped = true;}}}}"
      showBase64 (generateChacha20Poly1305Key bytes) `shouldBe` "UDKJ9PJ4zh6hDio6vuw0UhcSqk8njawoEziFz405238="
