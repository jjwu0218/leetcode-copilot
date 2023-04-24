# 1318. Minimum Flips to Make a OR b Equal to ct Array

'''
Given 3 positives numbers a, b and c. 
Return the minimum flips required in some bits of a and b to make ( a OR b == c ). 
(bitwise OR operation).
Flip operation consists of change any single bit 1 to 0 or change the bit 0 to 1 in their binary representation.

class Solution(object):
    def minFlips(self, a, b, c):
        """
        :type a: int
        :type b: int
        :type c: int
        :rtype: int
        """
'''

class Solution(object):
    def minFlips(self, a, b, c):
        """
        :type a: int
        :type b: int
        :type c: int
        :rtype: int
        """
        a = bin(a)[2:]
        b = bin(b)[2:]
        c = bin(c)[2:]
        a = a.zfill(max(len(a), len(b), len(c)))
        b = b.zfill(max(len(a), len(b), len(c)))
        c = c.zfill(max(len(a), len(b), len(c)))
        print(a, b, c)
        count = 0
        for i in range(len(c)):
            if c[i] == '0':
                if a[i] == '1':
                    count += 1
                if b[i] == '1':
                    count += 1
            else:
                if a[i] == '0' and b[i] == '0':
                    count += 1
        return count

