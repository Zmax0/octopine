{-# LANGUAGE OverloadedStrings #-}

module Common.Codec.VMess.ShakeSizeParserTest (spec) where

import Common.Codec.Chunk (PaddingLengthGenerator (nextPaddingLength))
import qualified Common.Codec.VMess.ShakeSizeParser as ShakeSizeParser
import Control.Monad.Trans.State.Strict (runState)
import Test.Hspec (Spec, describe, it, shouldSatisfy)

spec :: Spec
spec =
  describe "Common.Codec.VMess.ShakeSizeParser" $ do
    it "nextPaddingLength" $ do
      let initialParser = ShakeSizeParser.new "public static void bubbleSort(int[] arr) {int len = arr.length;for (int i = 0; i < len; i++) {for (int j = 1; j < len - i; j++) {if (arr[j - 1] > arr[j]) {int tmp = arr[j - 1];arr[j - 1] = arr[j];arr[j] = tmp;}}}}"
          paddingLengths =
            take 100 $
              map fst $
                drop 1 $
                  iterate
                    (\(_, parser) -> runState nextPaddingLength parser)
                    (0, initialParser)
      paddingLengths `shouldSatisfy` all (\paddingLength -> paddingLength >= 0 && paddingLength < 64)
