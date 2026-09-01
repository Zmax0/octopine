module Common.Exception (AppExceptionKind (..), AppException (..), throwApp, handleException) where

import Control.Exception (Exception (backtraceDesired, displayException), SomeAsyncException, SomeException, displayExceptionWithInfo, fromException, throwIO)
import Control.Monad.Catch (MonadThrow, throwM)
import GHC.Stack (CallStack, HasCallStack, callStack, prettyCallStack)
import System.Log.FastLogger (LogStr, ToLogStr (toLogStr))

data AppExceptionKind = ConfigError | ProtocolError | InvariantError | ExternalError deriving (Eq, Show)

data AppException = AppException AppExceptionKind String CallStack deriving (Show)

instance Exception AppException where
  displayException (AppException kind message stack') = "kind: " ++ show kind ++ ", message: " ++ message ++ "\n" ++ prettyCallStack stack'

  backtraceDesired _ = True

throwApp :: (MonadThrow m, HasCallStack) => AppExceptionKind -> String -> m a
throwApp kind message = throwM $ AppException kind message callStack

handleException :: (LogStr -> IO ()) -> SomeException -> IO ()
handleException logger exception = case fromException exception :: Maybe SomeAsyncException of
  Just asyncException -> throwIO asyncException
  Nothing -> logger $ toLogStr $ case fromException exception :: Maybe AppException of
    Just appException -> displayException appException
    Nothing -> unlines ["kind: " ++ show ExternalError, "exception:", displayExceptionWithInfo exception]
