# 1171. Remove Zero Sum Consecutive Nodes from Linked List

'''
Given the head of a linked list, we repeatedly delete consecutive sequences of nodes that sum to 0 until there are no such sequences.

After doing so, return the head of the final linked list.  You may return any such answer.

 

(Note that in the examples below, all sequences are serializations of ListNode objects.)
'''

# Definition for singly-linked list.
# class ListNode(object):
#     def __init__(self, val=0, next=None):
#         self.val = val
#         self.next = next
class Solution(object):
    def removeZeroSumSublists(self, head):
        """
        :type head: ListNode
        :rtype: ListNode
        """
        dummy = ListNode(0)
        dummy.next = head
        prefix = 0
        seen = {}
        node = dummy
        while node:
            prefix += node.val
            if prefix in seen:
                node = seen[prefix].next
                val = prefix + node.val
                while val != prefix:
                    del seen[val]
                    node = node.next
                    val += node.val
                seen[prefix].next = node.next
            else:
                seen[prefix] = node
            node = node.next
        return dummy.next