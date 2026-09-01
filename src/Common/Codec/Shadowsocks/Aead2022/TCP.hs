{-
    +----------------+
    |  length chunk  |
    +----------------+
    | u16 big-endian |
    +----------------+

    +---------------+
    | payload chunk |
    +---------------+
    |   variable    |
    +---------------+

    Request stream:
    +--------+------------------------+---------------------------+------------------------+---------------------------+---+
    |  salt  | encrypted header chunk |  encrypted header chunk   | encrypted length chunk |  encrypted payload chunk  |...|
    +--------+------------------------+---------------------------+------------------------+---------------------------+---+
    | 16/32B |     11B + 16B tag      | variable length + 16B tag |  2B length + 16B tag   | variable length + 16B tag |...|
    +--------+------------------------+---------------------------+------------------------+---------------------------+---+

    Response stream:
    +--------+------------------------+---------------------------+------------------------+---------------------------+---+
    |  salt  | encrypted header chunk |  encrypted payload chunk  | encrypted length chunk |  encrypted payload chunk  |...|
    +--------+------------------------+---------------------------+------------------------+---------------------------+---+
    | 16/32B |    27/43B + 16B tag    | variable length + 16B tag |  2B length + 16B tag   | variable length + 16B tag |...|
    +--------+------------------------+---------------------------+------------------------+---------------------------+---+
-}
{-
    Request fixed-length header:
    +------+------------------+--------+
    | type |     timestamp    | length |
    +------+------------------+--------+
    |  1B  | u64be unix epoch |  u16be |
    +------+------------------+--------+

    Request variable-length header:
    +------+----------+-------+----------------+----------+-----------------+
    | ATYP |  address |  port | padding length |  padding | initial payload |
    +------+----------+-------+----------------+----------+-----------------+
    |  1B  | variable | u16be |     u16be      | variable |    variable     |
    +------+----------+-------+----------------+----------+-----------------+
-}
{-
    Response fixed-length header:
    +------+------------------+----------------+--------+
    | type |     timestamp    |  request salt  | length |
    +------+------------------+----------------+--------+
    |  1B  | u64be unix epoch |     16/32B     |  u16be |
    +------+------------------+----------------+--------+

    Request variable-length header:
    +------+----------+-------+----------------+----------+-----------------+
    | ATYP |  address |  port | padding length |  padding | initial payload |
    +------+----------+-------+----------------+----------+-----------------+
    |  1B  | variable | u16be |     u16be      | variable |    variable     |
    +------+----------+-------+----------------+----------+-----------------+
-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module Common.Codec.Shadowsocks.Aead2022.TCP (SaltCache, checkSaltReplay, newHeader, withEih, initDecoder) where

import qualified BLAKE3
import Common.Codec (LeftoverByteString, PendingByteString)
import Common.Codec.Shadowsocks.Aead (AeadDecoder (..))
import qualified Common.Codec.Shadowsocks.Aead2022 as Aead2022
import qualified Common.Codec.Shadowsocks.Identity as Identity
import qualified Common.Codec.Shadowsocks.TCP.Session as Session
import qualified Common.Codec.Socks.Address as Address
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (Aead2022Blake3Aes128Gcm, Aead2022Blake3Aes256Gcm, keySize, tagSize))
import Common.Crypto.Aead.Authenticator (Authenticator, open, seal)
import Common.Crypto.Aead.NonceGenerator (IncreasingNonceGenerator)
import Common.Crypto.Aes (aes128EcbNoPaddingDecrypt, aes128EcbNoPaddingEncrypt, aes256EcbNoPaddingDecrypt, aes256EcbNoPaddingEncrypt)
import Common.Exception (AppExceptionKind (InvariantError, ProtocolError), throwApp)
import Common.Logger (loggers, trace_)
import Common.Network.Address (Address)
import Common.Protocol.Shadowsocks (Mode (Client, Server), Salt (Salt))
import Common.Protocol.Shadowsocks.Aead2022 (identitySubKey, supportEih)
import Common.Protocol.Shadowsocks.User (ServerUser (ServerUser), ServerUserManager, getUserByHash)
import Common.Util (encodeWord16BE, showByteString)
import Control.Concurrent.STM (atomically, readTVar)
import Control.Lens ((&), (.~))
import Control.Monad (when)
import Control.Monad.IO.Class (MonadIO (liftIO))
import Control.Monad.Trans.State.Strict (StateT, get, put, runState)
import Data.Binary.Builder (toLazyByteString)
import Data.Binary.Get (Get, getByteString, getInt64be, getWord16be, getWord8, runGetOrFail, skip)
import qualified Data.ByteArray.Sized as Sized
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Data.ByteString.Builder (int64BE)
import Data.Int (Int64)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Data.TinyLRU as TinyLRU
import Data.Void (Void)
import Data.Word (Word16, Word8)
import Formatting (format, int, (%))
import qualified StmContainers.Map as STMMap
import System.Clock (Clock (Monotonic), getTime)

$(loggers "c.c.s.a.TCP" ['trace_])

type FixedByteString = StrictByteString

type VariableByteString = StrictByteString

type NewHeaderResult = (FixedByteString, VariableByteString, LeftoverByteString)

type SaltCache = TinyLRU.TinyLRUCache Void

checkSaltReplay :: SaltCache -> Salt -> IO Bool
checkSaltReplay saltCache salt' = do
  now <- getTime Monotonic
  let key = T.pack $ show salt'
  atomically $ do
    previous <- STMMap.lookup key $ TinyLRU.lruCache saltCache
    _ <- TinyLRU.access now key salt' 30 saltCache
    case previous of
      Nothing -> pure False
      Just node -> not . TinyLRU.isExpired now <$> readTVar node

newHeader :: Mode -> Maybe Salt -> StrictByteString -> StateT (Authenticator IncreasingNonceGenerator) IO NewHeaderResult
newHeader mode (Just salt) msg = _newHeader mode salt msg
newHeader mode Nothing msg = _newHeader mode (Salt B.empty) msg

_newHeader :: Mode -> Salt -> StrictByteString -> StateT (Authenticator IncreasingNonceGenerator) IO NewHeaderResult
_newHeader mode (Salt salt) msg = do
  auth <- get
  timestamp <- liftIO Aead2022.newTimestamp
  let mode' = B.singleton $ toEnum $ fromEnum mode
      timestamp' = B.toStrict . toLazyByteString . int64BE $ timestamp
      length' = min 0xffff $ B.length msg
      (variable, leftover) = B.splitAt length' msg
      length'' = encodeWord16BE length'
      (fixed, auth') = runState (seal $ mode' <> timestamp' <> salt <> length'') auth
      (variable', auth'') = runState (seal variable) auth'
  put auth''
  return (fixed, variable', leftover)

initDecoder :: CipherKind -> Key -> Bool -> SaltCache -> ServerUserManager -> StrictByteString -> StateT Session.Session IO (Maybe (LeftoverByteString, PendingByteString, AeadDecoder))
initDecoder kind key hasUsers saltCache userManager msg = do
  session@(Session.Session mode address identity) <- get
  let tagSize' = tagSize kind
      saltLength = keySize kind
      requestSaltLength = if (mode == Server) then 0 else saltLength
      requireEih = mode == Server && supportEih kind && hasUsers
  let eihLength = if requireEih then 16 else 0
      headerLength = eihLength + 1 + 8 + requestSaltLength + 2 + tagSize'
  if B.length msg < saltLength + headerLength
    then pure Nothing
    else do
      let (salt', leftover') = B.splitAt saltLength msg
          salt'' = Salt salt'
          identity' = identity & Identity.requestSalt .~ Just salt''
          (sealedHeader, leftover'') = B.splitAt headerLength leftover'
      (decoder, identity'') <-
        if requireEih
          then do
            let eih = B.take 16 sealedHeader
            liftIO $ newDecoderWithEih kind key salt'' eih identity' userManager
          else pure (Aead2022.newDecoder kind key salt'', identity')
      let auth = _auth decoder
          (header, auth') = runState (open $ B.drop eihLength sealedHeader) auth
      (timestamp, requestSalt', length') <-
        case runGetOrFail (parseHeader mode saltLength) (B.fromStrict header) of
          Left (_, _, err) -> throwApp ProtocolError err
          Right (_, _, value) -> pure value
      liftIO $ Aead2022.validateTimestamp timestamp
      let ciphertextLength = fromIntegral length' + tagSize'
      if B.length leftover'' < ciphertextLength
        then pure Nothing
        else do
          let (ciphertext, leftover''') = B.splitAt ciphertextLength leftover''
              (plaintext, auth'') = runState (open ciphertext) auth'
              decoder' = _update auth'' decoder
              sessionWithIdentity = session & Session.identity .~ identity''
          session' <-
            case requestSalt' of
              Just salt''' -> do
                let identity''' = identity'' & Identity.requestSalt .~ Just salt'''
                liftIO $ _trace_ $ "get request header salt " ++ show salt'''
                return $ sessionWithIdentity & Session.identity .~ identity'''
              Nothing -> return sessionWithIdentity
          case (mode, address) of
            (Server, Nothing) ->
              case runGetOrFail parseAddress $ B.fromStrict plaintext of
                Left (_, _, err) -> throwApp ProtocolError err
                Right (plaintext', _, address') -> do
                  isSaltReplay <- liftIO $ checkSaltReplay saltCache salt''
                  when isSaltReplay $ throwApp ProtocolError $ "detected repeated nonce salt " <> show salt''
                  put $ session' & Session.address .~ Just address'
                  pure $ Just (leftover''', B.toStrict plaintext', decoder')
            _ -> do
              isSaltReplay <- liftIO $ checkSaltReplay saltCache salt''
              when isSaltReplay $ throwApp ProtocolError $ "detected repeated nonce salt " <> show salt''
              put session'
              pure $ Just (leftover''', plaintext, decoder')
  where
    _auth (DecodeLength auth') = auth'
    _auth (DecodeChunk auth' _) = auth'

    _update auth' (DecodeLength _) = DecodeLength auth'
    _update auth' (DecodeChunk _ l) = DecodeChunk auth' l

parseHeader :: Mode -> Int -> Get (Int64, Maybe Salt, Word16)
parseHeader mode saltLength = do
  streamType <- getWord8
  let expectedStreamType :: Word8 =
        case mode of
          Client -> fromIntegral $ fromEnum Server
          Server -> fromIntegral $ fromEnum Client
  when (streamType /= expectedStreamType) $ do
    fail $ TL.unpack $ format ("invalid stream type, expecting " % int % ", but found " % int) expectedStreamType streamType
  timestamp <- getInt64be
  requestSalt' <-
    if (mode == Client)
      then Just . Salt <$> getByteString saltLength
      else pure Nothing
  length' <- getWord16be
  pure (timestamp, requestSalt', length')

parseAddress :: Get Address
parseAddress = do
  address <- Address.decode
  paddingLength <- fromIntegral <$> getWord16be
  skip paddingLength
  pure address

newDecoderWithEih :: CipherKind -> Key -> Salt -> StrictByteString -> Identity.Identity -> ServerUserManager -> IO (AeadDecoder, Identity.Identity)
newDecoderWithEih kind key salt' eih identity userManager = do
  let subKey = identitySubKey key salt'
      userHash = B.take 16 eih
  userHash' <- case kind of
    Aead2022Blake3Aes128Gcm -> return $ aes128EcbNoPaddingDecrypt subKey userHash :: IO StrictByteString
    Aead2022Blake3Aes256Gcm -> return $ aes256EcbNoPaddingDecrypt subKey userHash :: IO StrictByteString
    _ -> throwApp InvariantError $ show kind ++ " doesn't support EIH"
  _trace_ $ "server EIH: " ++ showByteString eih ++ ", hash: " ++ showByteString userHash'
  user' <- atomically $ getUserByHash userManager userHash'
  case user' of
    Nothing -> throwApp ProtocolError $ "invalid client user identity " ++ showByteString userHash'
    Just user'' -> do
      let ServerUser name key' _ = user''
          identity' = identity & Identity.user .~ Just user''
      _trace_ $ "user [" ++ T.unpack name ++ "] chosen by EIH"
      return (Aead2022.newDecoder kind key' salt', identity')

withEih :: CipherKind -> Key -> [Key] -> Salt -> StrictByteString
withEih kind key identityKeys salt' = do
  let subKeys = [identityKey `identitySubKey` salt' | identityKey <- identityKeys]
      identityKeyHashes = [B.take 16 $ blake3Hash [identityKey] | identityKey <- drop 1 identityKeys ++ [key]]
  case kind of
    Aead2022Blake3Aes128Gcm -> B.concat $ zipWith aes128EcbNoPaddingEncrypt subKeys identityKeyHashes
    Aead2022Blake3Aes256Gcm -> B.concat $ zipWith aes256EcbNoPaddingEncrypt subKeys identityKeyHashes
    _ -> error $ show kind ++ " doesn't support EIH"

blake3Hash :: [StrictByteString] -> StrictByteString
blake3Hash bin = do
  let digest = BLAKE3.hash Nothing bin :: BLAKE3.Digest BLAKE3.DEFAULT_DIGEST_LEN
  Sized.unSizedByteArray (Sized.convert digest :: Sized.SizedByteArray BLAKE3.DEFAULT_DIGEST_LEN StrictByteString)
