{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}

module Common.Dice (Dice (roll), rollBytes) where

import Crypto.Random (getRandomBytes)
import Crypto.Random.Types (MonadRandom)
import Data.Binary.Get (getWord64be, runGet)
import Data.ByteArray (ByteArray)
import qualified Data.ByteString as B
import Data.Word (Word64)

class Dice a where
  roll :: (MonadRandom m) => m a

instance Dice Word64 where
  roll :: (MonadRandom m) => m Word64
  roll = runGet getWord64be . B.fromStrict <$> rollBytes 8

rollBytes :: (MonadRandom m, ByteArray ba) => Int -> m ba
rollBytes = getRandomBytes
