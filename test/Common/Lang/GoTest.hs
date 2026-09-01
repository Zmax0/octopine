{-# LANGUAGE OverloadedStrings #-}

module Common.Lang.GoTest (spec) where

import Common.Lang.Go (fnv1a32)
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Lang.Go" $ do
    it "fnv1a32" $ do
      fnv1a32 "public static void bubbleSort(int[] arr) {int len = arr.length;for (int i = 0; i < len; i++) {for (int j = 1; j < len - i; j++) {if (arr[j - 1] > arr[j]) {int tmp = arr[j - 1];arr[j - 1] = arr[j];arr[j] = tmp;}}}}"
        `shouldBe` 0xf18e710b
