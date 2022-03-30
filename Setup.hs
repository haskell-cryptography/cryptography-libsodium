module Main where

import Control.Monad (filterM, unless)
import Data.Functor (void)
import Data.List (isInfixOf, isSuffixOf)
import qualified Data.Map.Strict as Map
import Debug.Trace (traceId)
import Distribution.Simple
  ( compilerProperties,
    defaultMainWithHooks,
    postConf,
    simpleUserHooks,
  )
import Distribution.System (OS (Windows), buildOS)
import Distribution.Types.LocalBuildInfo (buildDir, compiler)
import System.Directory
  ( canonicalizePath,
    copyFile,
    doesFileExist,
    executable,
    findExecutable,
    getPermissions,
    getSymbolicLinkTarget,
    listDirectory,
    pathIsSymbolicLink,
    withCurrentDirectory,
  )
import System.FilePath (getSearchPath, takeDirectory, (<.>), (</>))
import System.Process (system)

main =
  defaultMainWithHooks $
    simpleUserHooks
      { postConf = \_args _configFlags _packageDescription localBuildInfo -> do
          -- Cabal, and indeed, GHC, don't understand the .lib extension on
          -- Windows, so we have the same name everywhere.
          let destinationPath = traceId $ buildDir localBuildInfo </> "libsodium" <.> "a"
          case buildOS of
            Windows -> do
              (chocoPath : _) <- filter (isInfixOf "Chocolatey") <$> getSearchPath
              (filter (isSuffixOf ".exe") <$> listDirectory chocoPath) >>= print
              mSh <- findExecutable "bash"
              mGCC <- findExecutable "gcc"
              case mSh of
                Nothing -> error "Cannot find bash on PATH. Aborting."
                Just shPath -> do
                  case mGCC of
                    Nothing -> putStrLn "Did not find GCC."
                    Just gccPath -> putStrLn gccPath >> putStrLn shPath
              -- We're in a bit of a bind when it comes to Windows. The chief
              -- problem is that the _only_ shell we have access to is CMD.EXE:
              -- this means that, even though we _could_ have Autotools access in
              -- theory (since GHC needs MinGW, which comes with the Autotools),
              -- we can't use them. Furthermore, we can't be clever and do a
              -- Visual Studio build, for three reasons:
              --
              -- 1. It would require our users to have Visual Studio installed,
              --    which is quite onerous.
              -- 2. We would have to detect where Visual Studio put the compiler,
              --    then drive a Visual Studio build, from the command line,
              --    _manually_. This is even _more_ onerous!
              -- 3. Even if we had 1 and 2, GHC on Windows relies on MinGW, so
              --    that might not even behave.
              --
              -- Thus, we use a bundled static prebuild. This is not ideal, as it
              -- bloats the distribution, but there's very little we can do about
              -- this.
              copyFile ("winlibs" </> "libsodium" <.> "a") destinationPath
            _ -> do
              -- Since everything else is some flavour of POSIX, we can use the
              -- Autotools to build in-place. This current (more involved) setup
              -- avoids triggering unnecessary rebuilds by checking if configure
              -- and/or make already ran.
              let workPath = "cbits" </> "libsodium-stable"
              let sourcePath = workPath </> "src" </> "libsodium" </> ".libs" </> "libsodium" <.> "a"
              let makefilePath = workPath </> "Makefile"
              configureRan <- doesFileExist makefilePath
              makeRan <- doesFileExist sourcePath
              unless configureRan (withCurrentDirectory workPath (void . system $ "./configure"))
              unless makeRan (withCurrentDirectory workPath (void . system $ "make -j"))
              copyFile sourcePath destinationPath
      }
