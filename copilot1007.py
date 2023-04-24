# 1007. Minimum Domino Rotations For Equal Row

'''
n a row of dominoes, tops[i] and bottoms[i] represent the top and bottom halves of the ith domino. (A domino is a tile with two numbers from 1 to 6 - one on each half of the tile.)

We may rotate the ith domino, so that tops[i] and bottoms[i] swap values.

Return the minimum number of rotations so that all the values in tops are the same, or all the values in bottoms are the same.

If it cannot be done, return -1.
'''

class Solution(object):
    def minDominoRotations(self, tops, bottoms):
        """
        :type tops: List[int]
        :type bottoms: List[int]
        :rtype: int
        """
        n = len(tops)
        if n == 0:
            return 0
        if n == 1:
            return 0
        
        def check(x):
            top = 0
            bottom = 0
            for i in range(n):
                if tops[i] != x and bottoms[i] != x:
                    return -1
                elif tops[i] != x:
                    top += 1
                elif bottoms[i] != x:
                    bottom += 1
            return min(top, bottom)
        
        res = check(tops[0])
        if res != -1 or tops[0] == bottoms[0]:
            return res
        else:
            return check(bottoms[0])