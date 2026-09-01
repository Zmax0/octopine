{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol.VMess.ID (newID, nextID, newAlterIDs) where

import Crypto.Hash (MD5 (MD5), hashWith)
import qualified Data.ByteArray as BA
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Data.ByteString.Lazy (LazyByteString)
import Data.List (genericTake)
import Data.Text (Text)
import qualified Data.UUID as UUID

class NewID a where
  newID :: a -> StrictByteString

instance NewID Text where
  newID text = case UUID.fromText text of
    Just u -> newID u
    Nothing -> error "illegal uuid"

instance NewID String where
  newID string = case UUID.fromString string of
    Just u -> newID u
    Nothing -> error "illegal uuid"

instance NewID UUID.UUID where
  newID = newID . UUID.toByteString

instance NewID LazyByteString where
  newID = newID . B.toStrict

instance NewID StrictByteString where
  newID bytes = BA.convert $ hashWith MD5 (bytes <> "c48619fe-8f02-49e0-b9e9-edf763e17e21")

nextID :: StrictByteString -> StrictByteString
nextID old = BA.convert $ hashWith MD5 (old <> "16167dc8-16b6-4e6d-b8bb-65dd68113a81")

newAlterIDs :: StrictByteString -> Int -> [StrictByteString]
newAlterIDs id' count
  | count <= 0 = []
  | otherwise = map newID (genericTake count (drop 1 (iterate nextID id')))
