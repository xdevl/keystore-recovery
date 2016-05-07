/* @copyright Copyright (c) 2016, XdevL
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* any later version.

* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

package com.xdevl.tool.ksrecovery;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.util.*;

public class Main
{
    // File path to the keystore to brute force
    static final String sKeyStoreFile="" ;

    // The key alias to brute force, if null or empty the first one found in the keystore is used
    static final String sAlias="" ;

    // The number of threads to use, if 0 the number of machine cores is used
    static final int sThreadNum=0 ;

    // Password length from which to start the attack
    static final int sMinimumLength=1 ;

    static final String sMinusCaseLetters[]={"a","b","c","d","e","f","g","h","i","j","k",
            "l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"} ;

    static final String sUpperCaseLetters[]={"A","B","C","D","E","F","G","H","I","J","K",
            "L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"} ;

    static final String sNumbers[]={"0","1","2","3","4","5","6","7","8","9"} ;

    static final String sSymbols[]={"#","@","$","!","*","&","?","%"} ;

    static final String sWords[]={} ;

    public static class BruteForceRunnable implements Runnable
    {
        private static volatile String sMatchPassword=null ;
        private static volatile long sCounter=0 ;

        public static String getMatchPassword() { return sMatchPassword; }
        public static long getCounter() { return sCounter; }

        public static String toString(List<String> symbols)
        {
            StringBuffer buffer=new StringBuffer() ;
            for(String symbol: symbols)
                buffer.append(symbol) ;
            return buffer.toString() ;
        }

        private KeyStore mKeyStore ;
        private String mAlias ;
        private int mLength ;
        private List<String> mThreadSymbols ;
        private List<String> mAllSymbols ;
        private LinkedList<String> mSymbolStack=new LinkedList<>() ;

        public BruteForceRunnable(String keyStoreFile, String alias, int length, List<String> allSymbols) throws IOException, GeneralSecurityException
        {
            this(keyStoreFile,alias,length,allSymbols,allSymbols) ;
        }

        public BruteForceRunnable(String keyStoreFile, String alias, int length, List<String> threadSymbols, List<String> allSymbols) throws IOException, GeneralSecurityException
        {
            mKeyStore=KeyStore.getInstance(KeyStore.getDefaultType()) ;
            mKeyStore.load(new FileInputStream(keyStoreFile),null) ;
            mAlias=alias ;
            mLength=length ;
            mThreadSymbols=threadSymbols ;
            mAllSymbols=allSymbols ;
        }

        @Override
        public void run()
        {
            try {
                bruteForceSubSet(mThreadSymbols);
            } catch(GeneralSecurityException e) {
                e.printStackTrace() ;
            }
        }

        public boolean bruteForceSubSet(List<String> symbolSubset) throws GeneralSecurityException
        {
            for(String symbol: symbolSubset)
            {
                mSymbolStack.push(symbol) ;
                if(bruteForce())
                    return true ;
               else mSymbolStack.pop() ;
            }
            return false ;
        }

        public boolean bruteForce() throws GeneralSecurityException
        {
            if(mSymbolStack.size()>=mLength)
            {
                String password=toString(mSymbolStack) ;
                try {
                    mKeyStore.getKey(mAlias,password.toCharArray()) ;
                    sMatchPassword=password ;
                    return true ;
                } catch(UnrecoverableKeyException e) {
                    // Wrong password, continue only if no other thread found a match
                    ++sCounter ;
                    return sMatchPassword!=null ;
                }
            }
            else return bruteForceSubSet(mAllSymbols) ;
        }
    }

    public static String getDefaultAlias(String fileName) throws GeneralSecurityException, IOException
    {
        KeyStore keystore=KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream(fileName),null) ;
        Enumeration<String> aliases=keystore.aliases() ;
        if(aliases.hasMoreElements())
            return aliases.nextElement() ;
        else throw new IOException("Keystore seems to be empty, no alias found...") ;
    }

    public static List<String> concat(String[] ...arrays)
    {
        List<String> result=new ArrayList<>() ;
        for(String[] array: arrays)
            result.addAll(Arrays.asList(array)) ;
        return result ;
    }

    public static void main(String[] args)
    {
        try {

            List<String> allSymbols=concat(sWords,sMinusCaseLetters,sUpperCaseLetters,sNumbers,sSymbols) ;
            String alias=sAlias!=null && !sAlias.isEmpty()?sAlias:getDefaultAlias(sKeyStoreFile) ;
            int threadNum=sThreadNum>0?sThreadNum:Runtime.getRuntime().availableProcessors() ;
            int subsetSize=allSymbols.size()/threadNum ;
            long counter=0 ;

            // Deal with the case where there are more threads than symbols (that's not likely to happen...)
            if(subsetSize==0)
            {
                subsetSize=1 ;
                threadNum=allSymbols.size() ;
            }

            System.out.println("Brute forcing password for key: "+alias+", using "+threadNum+" threads") ;

            for(int i=sMinimumLength;true;++i)
            {
                List<Thread> threads=new ArrayList<>(threadNum) ;
                for(int t=0;t<threadNum;++t)
                {
                    BruteForceRunnable runnable=new BruteForceRunnable(sKeyStoreFile,alias,i,
                            allSymbols.subList(t*subsetSize,(threadNum==t+1)?allSymbols.size():(t+1)*subsetSize),allSymbols) ;
                    Thread thread=new Thread(runnable) ;
                    threads.add(thread) ;
                    thread.start() ;
                }

                boolean allThreadsDied ;
                do
                {
                    allThreadsDied=true ;
                    for(Thread thread: threads)
                        allThreadsDied&=!thread.isAlive() ;

                    try { Thread.sleep(1000); } catch(InterruptedException e) {}
                    System.out.print(String.format("\r%d try/secs, total: %d, current password length: %d",
						BruteForceRunnable.getCounter()-counter,BruteForceRunnable.getCounter(),i)) ;
                    counter=BruteForceRunnable.getCounter() ;
                } while(!allThreadsDied) ;

                if(BruteForceRunnable.getMatchPassword()!=null)
                {
                    System.out.println("\nBrute force successfully completed with password: "+BruteForceRunnable.getMatchPassword()) ;
                    break ;
                }
            }

        } catch(GeneralSecurityException | IOException e) {
            e.printStackTrace() ;
        }
    }
}
