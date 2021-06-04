{- Problem:
      reimplement /dev/random in the language of my choice

   This exercise is a bad idea
    - /dev/random is
      - hardened
      - efficient
      - been examined by numerous experts

   Ignoring that, and pressing on with a fresh implementation I decided to appeal to authority & take a published algorithm.
   I found Fortuna.
   The following is a minimal draft of Fortuna in Haskell.
   Fortuna ended up being overkill ... more than necessary, and taking longer than expected to get skeleton code running.
   It has problems :-/

   The following code is based on chapter 9 of
      title: Design Principles and Practical Applications
      author:
         - Niels Ferguson
         - Bruce Schneier
         - Tadayoshi Kohno
      isbn: 978-0-470-47424-2

   It deviates in the following:
    - it omits functions not used for the core task of generating entropy
    - control of output is coarser -- instead of number of bytes you only get control of number of blocks
    - it checks statically (instead of dynamically) whether the generator has been seeded.
    - in RandomData it teases apart the defintion of the data from imperative control choosing


   Problems encountered
    - my unfamiliarity with libraries
    - I didn't understand Fortuna until I finished coding it ;-)
    - endless type conversions between Int-like types
    - Crypto, supposedly pure, has run-time errors!


   Won't do for example
     - print outputs nicely as hex (I haven't yet found the function that does so)
     - unit tests
     - checks on Int sizes
     - wire up logic for time-out
     - wire up logic for min pool size

   Opportunities to simplify code
     - maybe the functions need to be in a monad
     - ...
 -}

import           Crypto.Cipher.AES          (AES256)
import           Crypto.Cipher.Types        (BlockCipher(..), Cipher(..),nullIV)
import           Crypto.Error               (throwCryptoError)
import           Crypto.Hash                (hash, SHA256 (..), Digest)
import           Data.ByteString            (ByteString)
import qualified Data.ByteArray             as BA
import qualified Data.ByteString            as BS
import           Data.ByteString.Builder
import           Data.ByteString.Conversion
import qualified Data.ByteString.Lazy       as BSL
import           Data.Int
import           Data.Text.Encoding         (encodeUtf8)
import qualified Data.Text.IO               as TIO
import           System.IO                  (hFlush, stdout)


{-
function InitializeGenerator
output: G (Generator state)
  // Set the key K and counter C to zero.
  (K, C) ← (0, 0)
  // Package up the state.
  G ← (K, C)
  return G
-}

data GenState a = GS { key :: Key, count :: Counter }
instance Show (GenState a)
   where
      show (GS k c) = "{ key = " ++ (show $ k) ++ ", count = " ++ show c ++ "}"


-- types for readability
type Key      = Digest SHA256
type Counter  = Int32
type Length   = Int32
-- indexes for GenState
data New      = New
data Seeded   = Seeded


inject :: Int32 -> ByteString
inject = BS.concat . BSL.toChunks . toByteString . int32BE

initializeGenerator :: GenState New
initializeGenerator = GS (hash $ inject 0) 0 -- this deviates by using 'hash 0' instead of 0


{-
function Reseed
input: G // Generator state; modified by this function.
       s // New or additional seed.
  // Compute the new key using a hash function.
  K ← SHA_d-256(K||s)
  // Increment the counter to make it nonzero and mark the generator as seeded.
  // Throughout this generator, C is a 16-byte value treated as an integer
  // using the LSByte first convention.
  C ← C + 1
-}

type Seed = ByteString

digest2str :: Digest SHA256 -> ByteString
digest2str = BA.convert

reseed :: GenState a -> Seed -> GenState Seeded
reseed g s =
   GS
      { key   = hash $ BS.concat $ [digest2str $ key g,s]
      , count = 1 + count g
      }

{-
function GenerateBlocks
input: G // Generator state; modified by this function.
       k // Number of blocks to generate.
output: r // Pseudorandom string of 16k bytes.
  assert C = 0
  // Start with the empty string.
  r ← ε
  // Append the necessary blocks.
  for i = 1,...,k do
    r ← r||E(K, C)
    C ← C + 1
  od
  return r
-}


-- (
-- AES256 encryption
-- taken directly from https://stackoverflow.com/questions/42456724/how-to-use-haskell-cryptonite/42459006
encrypt :: ByteString -> ByteString -> ByteString
encrypt key plainData = ctrCombine ctx nullIV plainData
  where ctx :: AES256
        ctx = throwCryptoError $ cipherInit key
-- )

generateBlocks :: GenState Seeded -> Length -> (ByteString,GenState Seeded)
generateBlocks g k =
   let
      c = count g
      r = BS.concat $ map (encrypt $ digest2str $ key g) $ map inject $ [c .. c+k-1]
   in
      (r, GS{ key = key g, count = c+k })

{-
function PseudoRandomData
input: G // Generator state; modified by this function.
       n // Number of bytes of random data to generate.
output: r // Pseudorandom string of n bytes.
  // Limit the output length to reduce the statistical deviation from perfectly random outputs. Also ensure that the length is not negative.
  assert 0 ≤ n ≤ 2 20
  // Compute the output.
  r ← first-n-bytes(GenerateBlocks(G,ceiling(n/16)))
  // Switch to a new key to avoid later compromises of this output.
  K ← GenerateBlocks(G, 2)
  return r
-}

pseudoRandomData :: GenState Seeded -> Length -> (ByteString,GenState Seeded)
pseudoRandomData g n =
   let
      (r,g2) = generateBlocks g n
      (k,g3) = generateBlocks g 2
   in
      (r, GS{ key = hash k, count = count g3 })

{-
function InitializePRNG
output: R // prng state.
  // Set the 32 pools to the empty string.
  for i = 0..31 do
    P_i ← ε
  od
  // Set the reseed counter to zero.
  ReseedCnt ← 0
  // And initialize the generator.
  G ← InitializeGenerator()
  // Package up the state.
  R ← (G, ReseedCnt, P_0 .. P_31 )
  return R
-}

data PRNG_State a = PS { genstate  :: GenState a
                       , reseedCnt :: Counter
                       , pool      :: Int -> ByteString -- space leak
                       }
instance Show (PRNG_State a)
   where
      show (PS g r p) = "{ genstate = " ++ show g ++ ", reseedCnt = " ++ show r ++ ", pool = " ++ concat (map (show . p) [0..31]) ++ "}"

initializePRNG :: PRNG_State New
initializePRNG = PS
   { genstate  = initializeGenerator
   , reseedCnt = 0
   , pool      = const BS.empty
   }


{-
function RandomData
input: R // prng state, modified by this function.
       n // Number of bytes of random data to generate.
output: r // Pseudorandom string of bytes.
  if length(P_0) ≥ MinPoolSize ∧ last reseed > 100 ms ago then
    // We need to reseed.
    ReseedCnt ← ReseedCnt + 1
    // Append the hashes of all the pools we will use.
    s ← ε
    for i ∈ 0, ... , 31 do
      if 2^i | ReseedCnt then
        s ← s || SHAd-256(P_i)
        P_i ← ε
      fi
    od
    // Got the data, now do the reseed.
    Reseed(G, s)
  fi
  if ReseedCnt = 0 then
    // Generate error, prng not seeded yet
  else
    // Reseeds (if needed) are done. Let the generator that is part of R do the work.
    return PseudoRandomData(G, n)
  fi
-}

randomData_same_seed :: PRNG_State Seeded -> Length -> (ByteString, PRNG_State Seeded)
randomData_same_seed (PS gen1 cnt1 pool1) n =
   let
      (bs,gen2) = pseudoRandomData gen1 n
      r2        = PS gen2 cnt1 pool1
   in
      (bs,r2)


randomData_reseed :: PRNG_State Seeded -> Length -> (ByteString, PRNG_State Seeded)
randomData_reseed (PS gen1 cnt1 pool1) n =
   let
      len       = zeros (1 + cnt1)
      pool2 i   = if i<len then BS.empty else pool1 i
      gen2      = reseed gen1 $ BS.concat $ map pool1 $ [1..len]
      (bs,gen3) = pseudoRandomData gen2 n
      r2        = PS gen3 (1 + cnt1) pool2
   in
      (bs,r2)

zeros c =
   -- number of trailing 0's in the binary representation
   -- i.e. the largest i such that 2^i|c
   if 1 == c `mod` 2 || c < 1
   then 0
   else 1 + zeros (c `div` 2)

unit_zeros = print $ map zeros $ [1..16]

{-
function AddRandomEvent
input: R // prng state, modified by this function.
       s // Source number in range 0, . . . , 255.
       i // Pool number in range 0, . . . , 31. Each source must distribute its events over all the pools in a round-robin fashion.
       e // Event data. String of bytes; length in range 1, ... 32.
  // Check the parameters first.
  assert 1 ≤ length(e) ≤ 32 ∧ 0 ≤ s ≤ 255 ∧ 0 ≤ i ≤ 31
  // Add the data to the pool.
  P_i ← P_i || s || length(e) || e
-}

addRandomEvent :: PRNG_State Seeded -> Int32 -> Int -> ByteString -> PRNG_State Seeded
addRandomEvent r s i e =
   let
      p = BS.concat [ pool r i
                    , inject s
                    , inject $ fromIntegral $ BS.length $ e
                    , e
                    ]
   in
      PS (genstate r)
         (reseedCnt r)
         (\n -> if n==i then p else pool r n)



-- an example

main = eg
eg =
   let
      prng1      = initializePRNG
      prng2      = prng1 { genstate = reseed (genstate prng1) (inject 142857) }
      (b1,prng3) = randomData_same_seed prng2 1
      (b2,prng4) = randomData_same_seed prng3 60
      prng5      = addRandomEvent prng4 197 3 $ BA.pack [3, 141, 59, 26, 53, 58]
      (b3,prng6) = randomData_same_seed prng5 1
      -- ...
      prng_15     = prng6 { reseedCnt = 15 } -- fake up a history of 2^n-1 calls
      (b16a,prng_16a) = randomData_same_seed prng_15 1
      (b16b,prng_16b) = randomData_reseed    prng_15 1
   in
      do
         putStrLn "Intermediate states"
         putStrLn $ show prng1
         putStrLn $ show prng2
         putStrLn $ show prng3
         putStrLn $ show prng4
         putStrLn $ show prng5
         putStrLn $ show prng6
         putStrLn "Outputs"
         putStrLn $ show b1
         putStrLn $ show b2
         putStrLn $ show b3
         putStrLn "Difference between reseed & same seed"
         putStrLn $ show prng_16a
         putStrLn $ show b16a
         putStrLn $ show prng_16b
         putStrLn $ show b16b

