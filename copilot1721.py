# 1721. Swapping Nodes in a Linked List

'''
You are given the head of a linked list, and an integer k.

Return the head of the linked list after swapping the values of the kth node from the beginning and the kth node from the end (the list is 1-indexed).

'''

# Definition for singly-linked list.
# class ListNode(object):
#     def __init__(self, val=0, next=None):
#         self.val = val
#         self.next = next
class Solution(object):
    def swapNodes(self, head, k):
        """
        :type head: ListNode
        :type k: int
        :rtype: ListNode
        """
        # 1. Find the length of the linked list
        # 2. Find the kth node from the beginning
        # 3. Find the kth node from the end
        # 4. Swap the values of the two nodes
        # 5. Return the head
        
        # 1. Find the length of the linked list
        length = 0
        node = head
        while node:
            length += 1
            node = node.next
            
        # 2. Find the kth node from the beginning
        node = head
        for i in range(k-1):
            node = node.next
        kth_from_beginning = node
        
        # 3. Find the kth node from the end
        node = head
        for i in range(length-k):
            node = node.next
        kth_from_end = node
        
        # 4. Swap the values of the two nodes
        kth_from_beginning.val, kth_from_end.val = kth_from_end.val, kth_from_beginning.val
        
        # 5. Return the head
        return head