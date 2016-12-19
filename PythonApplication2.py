#!/usr/bin/env python 
#Program written to solve a challenge set by www.recruitahacker.net
from math import log
from time import sleep
from random import randint
from sys import platform
import re
import os
if platform == "linux" or platform == "linux2":
    clear = lambda: os.system('clear')
elif platform == "darwin":
    clear = lambda: os.system('clear')
elif platform == "win32":
    clear = lambda: os.system('cls')
text = open("decipher.txt", "r")
keyfound = False
keys2 = []
keygens = {0:""}
mutate = ""
tough = False
class VCipher:
        def __init__(self):
                self.Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                self.Frequencies = {
                        'A':84, 'B':23, 'C':21, 'D':46, 'E':116, 'F':20, 'G':25, 'H':49, 'I':76,
                        'J':2,  'K':5,  'L':38, 'M':34, 'N':66,  'O':66, 'P':15, 'Q':2,  'R':64,
                        'S':73, 'T':81, 'U':19, 'V':11, 'W':21,  'X':2,  'Y':24, 'Z':3
                }
 
                for k in self.Frequencies.keys():
                        self.Frequencies[k] = self.Frequencies[k]/1000.0
 
                self.Bans = {}
                for a in self.Alphabet:
                        x = (25 * self.Frequencies[a]) / (1 - self.Frequencies[a])
                        x = log(x) / log(10)
                        self.Bans[ord(a) - ord('A')] = x
 
        def TuringCheck(self, cipherText, keyLength, resultCount):
                ByLetter = {}
                for a in self.Alphabet:
                        ByLetter[a] = []
                        ordVal = ord(a) - ord('A')
                        for col in range(0, keyLength):
                                i = col
                                Evidence = 0
                                while i < len(cipherText):
                                        cipherVal = ord(cipherText[i]) - ord('A')
                                        diff = (cipherVal - ordVal) % 26
                                        Evidence += self.Bans[diff]
                                        i += keyLength
                                ByLetter[a].append(Evidence)
                Result = []
                for i in range(0, keyLength):
                        Column = {}
                        for l in self.Alphabet:
                                Column[l] = ByLetter[l][i]
                        Result.append(Column)
                return self._GetLikelyPasswords(Result, resultCount)
 
        def Encrypt(self, plainText, key):
                CipherText = ''
                KeyPos = 0
                for l in plainText:
                        if l in self.Alphabet:
                                lV = ord(l) - ord('A')
                                kV = ord(key[KeyPos].upper()) - ord('A')
                                val = (lV + kV) % 26
                                CipherText += chr(val + ord('A'))
                                KeyPos = (KeyPos + 1) % len(key)
                        elif l.upper() in self.Alphabet:
                                lV = ord(l) - ord('a')
                                kV = ord(key[KeyPos].lower()) - ord('a')
                                val = (lV + kV) % 26
                                CipherText += chr(val + ord('a'))
                                KeyPos = (KeyPos + 1) % len(key)
                        else:
                                CipherText += l
                return CipherText
 
        def Decrypt(self, cipherText, key):
                PlainText = ''
                KeyPos = 0
                for l in cipherText:
                        if l in self.Alphabet:
                                lV = ord(l) - ord('A')
                                kV = ord(key[KeyPos].upper()) - ord('A')
                                val = (lV - kV) % 26
                                PlainText += chr(val + ord('A'))
                                KeyPos = (KeyPos + 1) % len(key)
                        elif l.upper() in self.Alphabet:
                                lV = ord(l) - ord('a')
                                kV = ord(key[KeyPos].lower()) - ord('a')
                                val = (lV - kV) % 26
                                PlainText += chr(val + ord('a'))
                                KeyPos = (KeyPos + 1) % len(key)
                        else:
                                PlainText += l
                return PlainText
 
        def _Factor(self, n):
                return set(reduce(list.__add__, ([i, n//i] for i in range(1, int(n**0.5) + 1) if n % i == 0)))
 
        def _FindRepeatedSubstrings(self, cipherText, subLength):
                Subs = {}
                for i in range(0, len(cipherText) - subLength):
                        Substring = cipherText[i:i+subLength]
                        if cipherText.count(Substring) > 1:# and not Substring in Subs.keys():
                                Subs[Substring] = [m.start() for m in re.finditer(Substring, cipherText)]
                               
                return Subs
 
        def _AddToCountDict(self, d, v):
                if not v in d.keys():
                    d[v] = 1
                else: d[v] += 1

        def key_mutation(self, key):
            mutated_keys = []
            mutated_keys.append(key)
            for xyz in range(25):
                mutatedkey = ""
                keytomutate = randint(0, len(key)-1)
                timer = 0
                for L in key:
                    if timer == keytomutate:
                        mutatedkey += unichr((ord("Z") - randint(0, 24)))
                        timer += 1
                    else:
                        mutatedkey += L
                        timer += 1
                mutated_keys.append(str(mutatedkey))
            return mutated_keys

        def Crack(self, cipherText, pathToEnglishDict, candidateCount, passPercentage):
                global keygens
                global mutate
                with open(pathToEnglishDict) as f:
                        Dictionary = [x.strip('\n') for x in f.readlines()]
                Trimmed = self.Trim(cipherText)
                KeyLengthsDict = self.GetLikelyKeyLengths(Trimmed)
                KeyLengths = sorted(KeyLengthsDict, key= KeyLengthsDict.__getitem__, reverse=True)
                for length in KeyLengths:
                        timer = 0
                        leader = ""
                        #print "Testing Length: {0}".format(length)
                        if mutate == "":
                            Keys = self.TuringCheck(Trimmed, length, candidateCount)
                        else:
                            Keys = []
                        newkeys = "QWERTY"
                        if mutate != "":
                            newkeys = self.key_mutation(mutate)
                        for x in newkeys:
                            Keys.append(x)
                        for generated_key in Keys:
                                PlainText = self.TrimWithSpaces(self.Decrypt(cipherText, generated_key))
                                Words = PlainText.split()
                                EnglishWordCount = 0
                                max = 1.1
                                min = (passPercentage/100.0)
                                for word in Words:
                                    if word in Dictionary: EnglishWordCount += 1
                                Percentage = float(EnglishWordCount) / len(Words)
                                if Percentage >= min and Percentage < max:
                                        print "-------------"
                                        print "Cracked!"
                                        print ""
                                        print "Key = {0}".format(generated_key)
                                        print ""
                                        print self.Decrypt(cipherText, generated_key)
                                        keys2.append(generated_key)
                                        file = open("possiblekeys.txt", "a")
                                        output_text = str("\n \n" + "Key: " + generated_key + " " + str(int(Percentage*100))[0:3] + " %" + "\n \n" + cipherText + "\n \n" + self.Decrypt(cipherText, generated_key))
                                        file.write(output_text)
                                        file.close()
                                        return
                                if timer == 0:
                                    screenimage = str(int(Percentage*100))[0:3]
                                    if len(screenimage) == 1:
                                        gap = "  "
                                    elif len(screenimage) == 2:
                                        gap = " "
                                    print screenimage, "%", gap ,generated_key[:20]
                                    timer += 1
                                keygens[(Percentage*100)] = generated_key

                                

                print "Regenerating"
                cap = 0
                top = ""
                for key in keygens:
                    if key > cap:
                        cap = key
                        top = keygens[key]
                        mutate = keygens[key]
                def ihadtomakethisafunction(key):
                    clear()
                    print "Most accurate: ", top , str(cap)[:4], "%"
                    print self.Decrypt(cipherText, key), "\n"
                ihadtomakethisafunction(mutate)

 
 
 
        def GetLikelyKeyLengths(self, cyphertext):
                Substrings = self._FindRepeatedSubstrings(cyphertext, 3)
                Diffs = []
                for substring in Substrings.keys():
                        for i in range(0, len(Substrings[substring])-1):
                                Diffs.append(Substrings[substring][i+1] - Substrings[substring][i])
                FactorCounts = {}
 
                for d in Diffs:
                        Factors = self._Factor(d)
                        for f in Factors:
                                self._AddToCountDict(FactorCounts, f)
                return FactorCounts
 
 
        def _GetLikelyPasswords(self, columns, count):
                ColumnLetters = []
                Counts = []
                for ranks in columns:
                        ColumnLetters.append(sorted(ranks, key=ranks.__getitem__, reverse=True))
                        Counts.append(0)
 
                Results = []
                ResultCount = 0
                while ResultCount < count:
                        BestPass = ""
                        SmallestDiff = 1000
                        SmallestCol = -1
                        for i in range(0, len(columns)):
                                BestPass += ColumnLetters[i][Counts[i]]
                                if Counts[i] < 25:
                                        V1 = columns[i][ColumnLetters[i][Counts[i]]]
                                        V2 = columns[i][ColumnLetters[i][Counts[i]+1]]
                                        Diff = V1 - V2
                                        if Diff < SmallestDiff:
                                                SmallestDiff = Diff
                                                SmallestCol = i
                        Counts[SmallestCol] += 1
                        Results.append(BestPass)
                        ResultCount += 1
                return Results
 
        def TrimWithSpaces(self, text):
                result = ''
                for l in text:
                        if l.upper() in self.Alphabet or l == ' ':
                                result += l.upper()
                return result  
 
        def Trim(self, text):
                result = ''
                for l in text:
                        if l.upper() in self.Alphabet:
                                result += l.upper()
                return result
tocode = ""
for x in text:
    tocode += x
text.close()
tocode = tocode.lower()
lol = VCipher()
keytest = 26
match = 65
dicnum = 0
dic1 = "dict1.txt"
dic2 = "dict2.txt"
dic3 = "dict3.txt"
dics = [dic1, dic2, dic3]
attempts = 0
istough = ""
if istough == "s":
    tough = True
clear()
print ""


while len(keys2) < 1:
    lol.Crack(tocode, dics[dicnum], keytest, match)
    if attempts > 2:
        dicnum += 1
    if attempts > 10:
        break



