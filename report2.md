- ## Shop
  The Shop has suspicious sounding Fruitful flag, but we dont have enough money to buy it.
  The program only checks if the amount Quiet Quiches we buy is less than the the amount available, so its possible to buy a negative number of it and get the money required to buy the fruit.
  We get an output in the form of a list of numbers.
  Putting it in python and converting it to ascii letters we get the flag.
  ```python
  flaglis = "[112 105 99 111 67 84 70 123 98 52 100 95 98 114 111 103 114 97 109 109 101 114 95 55 57 55 98 50 57 50 99 125]"
  flag = ''.join(chr(int(i)) for i in flaglis[1:-1].split(' '))
  print(flag)
  ```
- ## vault-door-1
  From the `checkPassword` function, we can see that the password length 32. Also, all the letters of the password are there but they are jumbled up, so we can just extract them and put them together.
  ```python
  password = ['' for i in range(32)]
  password[0]  = 'd'
  password[29] = '9'
  password[4]  = 'r'
  password[2]  = '5'
  password[23] = 'r'
  password[3]  = 'c'
  password[17] = '4'
  password[1]  = '3'
  password[7]  = 'b'
  password[10] = '_'
  password[5]  = '4'
  password[9]  = '3'
  password[11] = 't'
  password[15] = 'c'
  password[8]  = 'l'
  password[12] = 'H'
  password[20] = 'c'
  password[14] = '_'
  password[6]  = 'm'
  password[24] = '5'
  password[18] = 'r'
  password[13] = '3'
  password[19] = '4'
  password[21] = 'T'
  password[16] = 'H'
  password[27] = '5'
  password[30] = '2'
  password[25] = '_'
  password[22] = '3'
  password[28] = '0'
  password[26] = '7'
  password[31] = 'e'
  print(password)
  ```
- ## Hurry Up! Wait!
  Decompiling the binary we see that there is some kind of delay function at the start and a lot of functions following it
  one of these function after decompiling gives
  ```c
  void FUN_00102616(void)  
  {
    void FUN_00102616(void)
    ada__text_io__put__4(&DAT_00102cd8,&DAT_00102cb8);
    return;
  }
  ```
  checking `DAT_00102cd8` we see the hex value `70` which is ascii for p
  doing the same for the next function we see `69` which is hex for i
  We can assume that these letters correspond to some flag `picoCTF{....}`
  doing the same for every function we get `picoCTF{d15a5m_ftw_eab78e4}`
- ## Vault Door 3
  We see that the following function takes the flag and jumbles it up  and compares it to the string `jU5t_a_sna_3lpm18g947_u_4_m9r54f`
  ``` java
  public boolean checkPassword(String password) {
        if (password.length() != 32) {
            return false;
        }
        char[] buffer = new char[32];
        int i;
        for (i=0; i<8; i++) {
            buffer[i] = password.charAt(i);
        }
        for (; i<16; i++) {
            buffer[i] = password.charAt(23-i);
        }
        for (; i<32; i+=2) {
            buffer[i] = password.charAt(46-i);
        }
        for (i=31; i>=17; i-=2) {
            buffer[i] = password.charAt(i);
        }
        String s = new String(buffer);
        return s.equals("jU5t_a_sna_3lpm18g947_u_4_m9r54f");
    }
  ```
  the following python script can dejumble the string
  ```python
  password = ['' for i in range(32)]
  buffer = "jU5t_a_sna_3lpm18g947_u_4_m9r54f"
  for i in range(8):
      password[i] = buffer[i]
  for i in range(8, 16):
      password[23-i] = buffer[i]
  for i in range(16,32,2):
      password[46-i] = buffer[i]
  for i in range(31, 16, -2):
      password[i] = buffer[i]
  print(''.join(password))
  ```
  which gives `jU5t_a_s1mpl3_an4gr4m_4_u_79958f`
- ## Vault Door 4
  In the code we can see an array with bytes, converting these bytes back to ascii values and then characters we get `jU5t_4_bUnCh_0f_bYt3s_8f4a6cbf3b`
  ```java
  import java.util.*;
  
  class VaultDoor4 {
      public static void main(String args[]) {
          VaultDoor4 vaultDoor = new VaultDoor4();
          Scanner scanner = new Scanner(System.in);
          System.out.print("Enter vault password: ");
          String userInput = scanner.next();
  	String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
  	if (vaultDoor.checkPassword(input)) {
  	    System.out.println("Access granted.");
  	} else {
  	    System.out.println("Access denied!");
          }
      }
  
      // I made myself dizzy converting all of these numbers into different bases,
      // so I just *know* that this vault will be impenetrable. This will make Dr.
      // Evil like me better than all of the other minions--especially Minion
      // #5620--I just know it!
      //
      //  .:::.   .:::.
      // :::::::.:::::::
      // :::::::::::::::
      // ':::::::::::::'
      //   ':::::::::'
      //     ':::::'
      //       ':'
      // -Minion #7781
      public boolean checkPassword(String password) {
          byte[] passBytes = password.getBytes();
          byte[] myBytes = {
              106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
              0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
              0142, 0131, 0164, 063 , 0163, 0137, 070 , 0146,
              '4' , 'a' , '6' , 'c' , 'b' , 'f' , '3' , 'b' ,
          };
          for (int i=0; i<32; i++) {
              if (passBytes[i] != myBytes[i]) {
                  return false;
              }
          }
          return true;
      }
  }
  ```
- ## Vault Door 5
  The code takes the password, converts it into urlencoded form and then converts that into base64 and compares that to `JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTY1JTMzJTMxJTM1JTMyJTYyJTY2JTM0`.
  Decoding it from base64 using [https://www.base64decode.org/](https://www.base64decode.org/) we get `%63%30%6e%76%33%72%74%31%6e%67%5f%66%72%30%6d%5f%62%61%35%65%5f%36%34%5f%65%33%31%35%32%62%66%34`. This is an urlencoded string which if convert back we get `c0nv3rt1ng_fr0m_ba5e_64_e3152bf4`.

- ## Vault Door 6

- ## Vault Door 7
  The function takes the 8bit ascii value of every character and composes them together to form a 32bit number.
  Each 8bit part of the 32bit numbers can be decomposed back into a 8bit number that can be reinterpreted as a character.
  ```python
  x = [1096770097, 1952395366, 1600270708, 1601398833, 1716808014, 1734304867, 942695730, 942748212]
  for i in x:
    print(chr((i>>24)&0xff), chr((i>>16)&0xff), chr((i>>8)&0xff), chr(i&0xff), sep='', end='')
  ```
  This script gives `A_b1t_0f_b1t_sh1fTiNg_dc80e28124`
- ## Vault Door 8
  The following code is given:
  ```java

  // These pesky special agents keep reverse engineering our source code and then
  // breaking into our secret vaults. THIS will teach those sneaky sneaks a
  // lesson.
  //
  // -Minion #0891
  import java.util.*;
  import javax.crypto.Cipher;
  import javax.crypto.spec.SecretKeySpec;
  import java.security.*;
  
  class VaultDoor8 {
      public static void main(String args[]) {
          Scanner b = new Scanner(System.in);
          System.out.print("Enter vault password: ");
          String c = b.next();
          String f = c.substring(8, c.length() - 1);
          VaultDoor8 a = new VaultDoor8();
          if (a.checkPassword(f)) {
              System.out.println("Access granted.");
          } else {
              System.out.println("Access denied!");
          }
      }
  
      public char[] scramble(String password) {/* Scramble a password by transposing pairs of bits. */
          char[] a = password.toCharArray();
          for (int b = 0; b < a.length; b++) {
              char c = a[b];
              c = switchBits(c, 1, 2);
              c = switchBits(c, 0, 3);
              /* c = switchBits(c,14,3); c = switchBits(c, 2, 0); */ c = switchBits(c, 5, 6);
              c = switchBits(c, 4, 7);
              c = switchBits(c, 0, 1);
              /* d = switchBits(d, 4, 5); e = switchBits(e, 5, 6); */ c = switchBits(c, 3, 4);
              c = switchBits(c, 2, 5);
              c = switchBits(c, 6, 7);
              a[b] = c;
          }
          return a;
      }
  
      public char switchBits(char c, int p1, int p2) {
          /*
           * Move the bit in position p1 to position p2, and move the bit
           * that was in position p2 to position p1. Precondition: p1 < p2
           */ char mask1 = (char) (1 << p1);
          char mask2 = (char) (1 << p2);
          /* char mask3 = (char)(1<<p1<<p2); mask1++; mask1--; */ char bit1 = (char) (c & mask1);
          char bit2 = (char) (c & mask2);
          /*
           * System.out.println("bit1 " + Integer.toBinaryString(bit1));
           * System.out.println("bit2 " + Integer.toBinaryString(bit2));
           */ char rest = (char) (c & ~(mask1 | mask2));
          char shift = (char) (p2 - p1);
          char result = (char) ((bit1 << shift) | (bit2 >> shift) | rest);
          return result;
      }
  
      public boolean checkPassword(String password) {
          char[] scrambled = scramble(password);
          char[] expected = {
                  0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4, 0xF0, 0x77, 0xA4, 0xD0, 0xC5, 0x77, 0xF4, 0x86, 0xD0,
                  0xA5, 0x45, 0x96, 0x27, 0xB5, 0x77, 0xE0, 0x95, 0xF1, 0xE1, 0xE0, 0xA4, 0xC0, 0x94, 0xA4 };
          return Arrays.equals(scrambled, expected);
      }
  }
  ```
  the scramble function takes every character, and jumbles up its bits and stores it in an array, we can just reverse the indices in switchBits so that we get the original character ascii value back.
  ```java

  // These pesky special agents keep reverse engineering our source code and then
  // breaking into our secret vaults. THIS will teach those sneaky sneaks a
  // lesson.
  //
  // -Minion #0891
  import java.util.*;
  import javax.crypto.Cipher;
  import javax.crypto.spec.SecretKeySpec;
  import java.security.*;
  
  class VaultDoor8 {
      public static void main(String args[]) {
          /*Scanner b = new Scanner(System.in);
          System.out.print("Enter vault password: ");
          String c = b.next();
          String f = c.substring(8, c.length() - 1);
          */
          VaultDoor8 a = new VaultDoor8();
          /*if (a.checkPassword(f)) {
              System.out.println("Access granted.");
          } else {
              System.out.println("Access denied!");
          }*/
          char[] expected = {
              0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4, 0xF0, 0x77, 0xA4, 0xD0, 0xC5, 0x77, 0xF4, 0x86, 0xD0,
              0xA5, 0x45, 0x96, 0x27, 0xB5, 0x77, 0xE0, 0x95, 0xF1, 0xE1, 0xE0, 0xA4, 0xC0, 0x94, 0xA4 };
          System.out.println(a.scramble(expected));
      }
  
      public char[] scramble(char [] a) {/* Scramble a password by transposing pairs of bits. */
          for (int b = 0; b < a.length; b++) {
              char c = a[b];
              c = switchBits(c, 6, 7);
              c = switchBits(c, 2, 5);
              /* d = switchBits(d, 4, 5); e = switchBits(e, 5, 6); */ c = switchBits(c, 3, 4);
              c = switchBits(c, 0, 1);
              c = switchBits(c, 4, 7);
              /* c = switchBits(c,14,3); c = switchBits(c, 2, 0); */ c = switchBits(c, 5, 6);
              c = switchBits(c, 0, 3);
              c = switchBits(c, 1, 2);
              a[b] = c;
          }
          return a;
      }
  
      public char switchBits(char c, int p1, int p2) {
          /*
           * Move the bit in position p1 to position p2, and move the bit
           * that was in position p2 to position p1. Precondition: p1 < p2
           */ char mask1 = (char) (1 << p1);
          char mask2 = (char) (1 << p2);
          /* char mask3 = (char)(1<<p1<<p2); mask1++; mask1--; */ char bit1 = (char) (c & mask1);
          char bit2 = (char) (c & mask2);
          /*
           * System.out.println("bit1 " + Integer.toBinaryString(bit1));
           * System.out.println("bit2 " + Integer.toBinaryString(bit2));
           */ char rest = (char) (c & ~(mask1 | mask2));
          char shift = (char) (p2 - p1);
          char result = (char) ((bit1 << shift) | (bit2 >> shift) | rest);
          return result;
      }
      /*
      public boolean checkPassword(String password) {
          char[] scrambled = scramble(password);
          char[] expected = {
                  0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4, 0xF0, 0x77, 0xA4, 0xD0, 0xC5, 0x77, 0xF4, 0x86, 0xD0,
                  0xA5, 0x45, 0x96, 0x27, 0xB5, 0x77, 0xE0, 0x95, 0xF1, 0xE1, 0xE0, 0xA4, 0xC0, 0x94, 0xA4 };
          return Arrays.equals(scrambled, expected);
      }
      */
  }
  ```
  Using this code we get ```s0m3_m0r3_b1t_sh1fTiNg_2e762b0ab```

