module Common.Protocol.VMess (now, version, timestamp) where

import Data.Int (Int64)
import Data.Time.Clock (getCurrentTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import GHC.Word (Word8)
import System.Random.Stateful (randomRIO)

version :: Word8
version = 1

now :: IO Int64
now = floor . utcTimeToPOSIXSeconds <$> getCurrentTime

timestamp :: Int64 -> IO Int64
timestamp delta = (+) <$> now <*> randomRIO (0, 2 * delta)
