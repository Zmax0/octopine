{-# LANGUAGE TemplateHaskellQuotes #-}

module Common.Logger (initRootLevel, LogLevel (..), trace_, debug_, info_, warn_, error_, loggers) where

import Common (findArg)
import Data.Char (toLower)
import Data.IORef (IORef, writeIORef)
import Data.Maybe (fromMaybe)
import Data.Time (defaultTimeLocale)
import Data.Time.Format (formatTime)
import Data.Time.LocalTime (getZonedTime)
import GHC.Base (when)
import GHC.Conc (myThreadId)
import GHC.Conc.Sync (showThreadId, threadLabel)
import GHC.IO (unsafePerformIO)
import GHC.IORef (newIORef, readIORef)
import Language.Haskell.TH
  ( Dec,
    Name,
    Q,
    Quote (newName),
    Specificity (SpecifiedSpec),
    TyVarBndr (PlainTV),
    Type (AppT, ArrowT, ConT, ForallT, TupleT, VarT),
    appE,
    clause,
    funD,
    litE,
    mkName,
    nameBase,
    normalB,
    sigD,
    stringL,
    varE,
    varP,
  )
import System.Directory (createDirectoryIfMissing)
import System.Log.FastLogger (LoggerSet, ToLogStr, defaultBufSize, toLogStr)
import System.Log.FastLogger.LoggerSet (newFileLoggerSet, newFileLoggerSetN, newStderrLoggerSet, newStdoutLoggerSetN, pushLogStrLn)

loggerDir :: String
loggerDir = "log"

data LogLevel = TRACE | DEBUG | INFO | WARN | ERROR deriving (Eq, Enum, Ord)

instance Show LogLevel where
  show TRACE = "TRACE"
  show DEBUG = "DEBUG"
  show INFO = "INFO "
  show WARN = "WARN "
  show ERROR = "ERROR"

defaultLevel :: LogLevel
defaultLevel = INFO

getRootLevel :: [String] -> Maybe LogLevel
getRootLevel args = do
  mapLevel . map toLower <$> findArg args "-root.level"

mapLevel :: String -> LogLevel
mapLevel "trace" = TRACE
mapLevel "debug" = DEBUG
mapLevel "info" = INFO
mapLevel "warn" = WARN
mapLevel "error" = ERROR
mapLevel _ = defaultLevel

initRootLevel :: [String] -> IO ()
initRootLevel args = do
  let level = fromMaybe defaultLevel $ getRootLevel args
  writeIORef rootLevel $ Just level
  info__ "Logger" $ return $ "root level [" ++ show level ++ "]"

{-# NOINLINE rootLevel #-}
rootLevel :: IORef (Maybe LogLevel)
rootLevel = unsafePerformIO $ newIORef $ Just defaultLevel

{-# NOINLINE stdout #-}
stdout :: IORef LoggerSet
stdout = unsafePerformIO $ do
  newStdoutLoggerSetN defaultBufSize (Just 1) >>= newIORef

{-# NOINLINE stderr #-}
stderr :: IORef LoggerSet
stderr = unsafePerformIO $ do
  newStderrLoggerSet defaultBufSize >>= newIORef

{-# NOINLINE appFile #-}
appFile :: IORef LoggerSet
appFile = unsafePerformIO $ do
  createDirectoryIfMissing True loggerDir
  newFileLoggerSetN defaultBufSize (Just 1) (loggerDir ++ "/app.log") >>= newIORef

{-# NOINLINE errorFile #-}
errorFile :: IORef LoggerSet
errorFile = unsafePerformIO $ do
  createDirectoryIfMissing True loggerDir
  newFileLoggerSet defaultBufSize (loggerDir ++ "/error.log") >>= newIORef

type Logger = String

_log :: (ToLogStr str) => [IORef LoggerSet] -> LogLevel -> Logger -> IO str -> IO ()
_log globalLogger level logger msg = do
  rootLevel' <- readIORef rootLevel
  let flag = maybe True (<= level) rootLevel'
  when flag $ __log globalLogger level logger msg

__log :: (ToLogStr str) => [IORef LoggerSet] -> LogLevel -> Logger -> IO str -> IO ()
__log globalLogger level logger msg = do
  now <- getZonedTime
  thread <- myThreadId
  threadLabel' <- threadLabel thread
  let timeStr = formatTime defaultTimeLocale "%Y-%m-%d %H:%M:%S%3Q" now
      levelStr = show level
      threadId = showThreadId thread
      threadStr = fromMaybe threadId threadLabel'
      prefix = timeStr ++ " " ++ levelStr ++ " [" ++ threadStr ++ "] " ++ logger ++ " - "
  msg' <- msg
  let line = toLogStr prefix <> toLogStr msg'
  globalLoggers <- mapM readIORef globalLogger
  mapM_ (`pushLogStrLn` line) globalLoggers

trace_ :: (ToLogStr str) => Logger -> IO str -> IO ()
trace_ = _log [stdout, appFile] TRACE

debug_ :: (ToLogStr str) => Logger -> IO str -> IO ()
debug_ = _log [stdout, appFile] DEBUG

info_ :: (ToLogStr str) => Logger -> IO str -> IO ()
info_ = _log [stdout, appFile] INFO

info__ :: (ToLogStr str) => Logger -> IO str -> IO ()
info__ = __log [stdout, appFile] INFO

warn_ :: (ToLogStr str) => Logger -> IO str -> IO ()
warn_ = _log [stdout, appFile] WARN

error_ :: (ToLogStr str) => Logger -> IO str -> IO ()
error_ = _log [stderr, errorFile] ERROR

loggers :: Logger -> [Name] -> Q [Dec]
loggers logger levels = concat <$> mapM (loggers_ logger) levels

loggers_ :: Logger -> Name -> Q [Dec]
loggers_ logger levels = do
  msg <- newName "msg"
  let level = nameBase levels
      name = mkName ("_" ++ level)
      str = mkName "str"
      levelE = varE levels
      loggerE = litE (stringL logger)
      returnE = appE (varE 'return) (varE msg)
      loggerB = appE (appE levelE loggerE) returnE
      -- forall str. ToLogStr str => str -> IO ()
      sigType = ForallT [PlainTV str SpecifiedSpec] [AppT (ConT ''ToLogStr) (VarT str)] (AppT (AppT ArrowT (VarT str)) (AppT (ConT ''IO) (TupleT 0)))
  sig <- sigD name (return sigType)
  fun <- funD name [clause [varP msg] (normalB loggerB) []]
  return [sig, fun]
