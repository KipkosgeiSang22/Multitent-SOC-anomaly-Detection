# transactions = [
#     {"category":"electronics", "revenue":150.00},
#     {"category":"Apparel", "revenue": 45.40},
#     {"category":"electronics", "revenue":200.00},
#     {"category":"home & Kitchen", "revenue": 89.99},
#     {"category": "Apparel", "revenue":15.00}
# ]
# # def aggregrate_revenue(transactions):
# #     summary = {}
# #     for entry in transactions:
# #         category = entry.get("category")
# #         revenue = entry.get("revenue", 0)

# #         if category in summary:
# #             summary[category] += revenue
# #         else:
# #             summary[category] = revenue
# #     return summary
# # a = aggregrate_revenue(transactions)
# # print(a.get("electronics"))

# data = [10, 20, 30, 40, 50, 60]
# window_size = 3

# # def moving_average(data, window_size):
# #     if window_size <= 0 or not data:
# #         return []
    
# #     averages = []
# #     for i in range(len(data) - window_size + 1):
# #         window = data[i:i + window_size]
# #         window_avg = sum(window)/ window_size
# #         averages.append(window_avg)
# #     return averages
# # print(moving_average(data, window_size))
# import json
# logs = [
#     '{"user_id": 101, "action":"login"}',
#     'server successfully started',
#     '{"action":"logout"}',
#     '{"user_id":102, "action":"click"}',
#     '{"user_id":"malformed_json"'
# ]

# # def extract_valid_users(logs):
# #     valid_users = []
# #     for log in logs:
# #         try:
# #             parsed_data = json.loads(log)
# #             if "user_id" in log:
# #                 valid_users.append(parsed_data["user_id"])
# #         except json.JSONDecodeError:
# #             continue
# #     return valid_users
# # print(extract_valid_users(logs))

# # def chunk_array(data, size):
# #     if size <= 0:
# #         return []
# #     return [data[i:i+size] for i in range(0, len(data), size)]
# # data = [1,2,3,4,6,7,8,9]
# # size = 2
# # print(chunk_array(data, size))
# # from datetime import datetime
# # def minutes_between(time1, time2):
# #     format_str = "%Y-%m-%dT%H:%M:%SZ"
# #     dt1 = datetime.strptime(time1, format_str)
# #     dt2 = datetime.strptime(time2, format_str)

# #     delta = abs(dt2-dt1)
# #     return int(delta.total_seconds()/60)
# # def get_nth_fibonacci(n):
# #     if n <= 0:
# #         return 0
# #     elif  n == 1:
# #         return 1
# #     prev = 0
# #     current = 1
# #     for _ in range(2, n+1):
# #         next_num = prev + current
# #         prev = current
# #         current = next_num
# #     return current
# # print(get_nth_fibonacci(50))
# # def find_nth_term(first_term, difference, n):
# #     if n < 1:
# #         raise ValueError("n must be 1 or greater.")
# #     return first_term + (n-1)* difference
# from urllib.parse import urlencode, urlunparse, urlparse
# def build_url(base_url, query_params):
#     if not query_params:
#         return base_url
#     encoded_query = urlencode(query_params)
#     url_parts = list(urlparse(base_url))
#     if url_parts[4]:
#         url_parts[4] = f"{url_parts}&{encoded_query}"
#     else:
#         url_parts[4] = encoded_query
#     return urlunparse(url_parts)
# base = "https://api.xobriq.com/v1/search"
# params = {
#     "q":"cyber security metrics",
#     "limit": 50,
#     "user_email": "jsang542@gmail.com"
# }
# final_url = build_url(base, params)
# print(final_url)

from time import time
from collections import defaultdict
MAX_ATTEMPS = 5
WINDOW = 600
LOCKOUT = 900
attempts = defaultdict(list)
locked_until = {}
def record_attempt(user_id: str) ->dict:
    now = time()
    if user_id in locked_until:
        if now < locked_until[user_id]:
            remaining = int(locked_until[user_id] - now)
            return {"allowed":"False", "reason":"locked", "retry_after":"remaining"}
        else:
            del locked_until[user_id]
            attempts[user_id] = []
    attempts[user_id] = [t for t in attempts[user_id] if now - t < WINDOW] 
    attempts[user_id].append(now)

    if len(attempts[user_id]) > MAX_ATTEMPS:
        locked_until[user_id] = now + LOCKOUT
        attempts[user_id] = []
        return {"allowed":"false","reason":"account_lockedout", "retry_after": LOCKOUT}
    return {"allowed":True, "attempts":len(attempts[user_id])}

# SELECT DISTINCT a.user_id
# FROM Login_events a
# JOIN login_events b
# ON a.user_id == b.user_id AND b.timestamp > a.timestamp AND b.timestamp < a.timestamp + INTERVAL '24 hours'
# WHERE a.success = true AND b.success = true GROUP by a.user_id, a.timestamp HAVING count(DISTICT ip_to_country(b.ip_address))
# from fastapi import FastAPI, HTTPException, status, Depends, Request
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from sqlalchemy.ext.asyncio import AsyncSession
# import jwt
# app = FastAPI()
# security = HTTPBearer
# SECRET= "36743927983"
# TRANSACTIONS_DB = {
#     "user_1":[{"id":"t1", "amount": 500, "currnecy":"KES"}],
#     "user_2":[{"id":"t2", "amount":1200, "currency":"KES"}]
# }

# def get_current_user(
#         creds: HTTPAuthorizationCredentials = Depends(security)
# )->str:
#     try:
#         payload = jwt.decode(creds.credentials, SECRET, algorithms=["HS256"])
#         return payload["user_id"]
#     except jwt.ExpiredSignatureError:
#         raise HTTPException(status=401, detail="token expired")
#     except jwt.InvalidTokenError:
#         raise HTTPException(status_code=401, detail="Invalid token")
    
# @app.get("/transactions")
# def get_transactions(user_id: str = Depends(get_current_user)):
#     return TRANSACTIONS_DB.get(user_id, [])


# @app.post("/callbacks/mpesa")
# async def mpesa_callback(
#     request:Request,
#     db: AsyncSession= Depends(get_db)
# )

def first_unique_character(s: str) -> str:
    count = {}
    for ch in s:
        count[ch] = count.get(ch, 0) + 1
    for ch in s:
        if count[ch] == 1:
            return ch
    return ""

def is_valid(s:str) -> bool:
    stack = []
    pairs = {"(":")", "[":"]","{":"}"}
    for ch in s:
        if ch in "({[":
            stack.append(ch)
        elif ch in ")}]":
            if not stack:
                return False
            if stack[-1] != pairs[ch]:
                return False
            stack.pop()
    return len(stack) == 0
data = [2,7,5,8]
def two_sum(data, target):
    seen = {}
    for i, num in enumerate(data):
        difference = target-num
        if difference in seen:
            return [seen[difference], i]
        seen[difference] = i
    return []

class Node:
    def __init__(self, val):
        self.val = val
        self.next = None
    def reverse_list(head: None) :
        prev = None
        current = None 
        
        while current:
            next_node = current.next
            current.next = prev
            prev = current

class MyQueue:
    def __init__(self):
        self.inbox = []
        self.outbox = []
    def enqueue(self, val):
        self.inbox.append(val)
    def dequeue(self):
        if not self.outbox:
            while self.inbox:
                self.outbox.append(self.inbox.pop())
        if not self.outbox:
            raise IndexError("queue is empty")
        return self.outbox.pop()
    
q = MyQueue()
q.enqueue(1)
q.enqueue(2)
q.enqueue(3)
# print(q.dequeue())
def longest_substring(s:str) -> int:
    seen = {}
    left = 0
    max_len = 0

    for  right, ch in enumerate(s):
        if ch in seen and seen[ch] >= left:
            left = seen[ch] + 1
        seen[ch] = right
        max_len = max(max_len, right - left + 1)
    return max_len

def binary_search(nums:list, target:int)->int:
    left, right = 0, len(nums) - 0
    while left <= right:
        mid = (right - left) // 2
        if nums[mid] == target:
            return mid
        elif nums[mid] < target:
            left = mid+1
        else:
            right = mid -1
    return -1

def flatten(lst: list) -> list:
    result = []
    for item in lst:
        if isinstance(item, list):
            result.extend(flatten(item))
        else:
            result.append(item)
    return result

from collections import defaultdict
def group_anagrams(words:list) ->list:
    groups = defaultdict(list)
    for word in words:
        key = "".join(sorted(word))
        groups[key].append(word)

    return list(groups.values())

# print(group_anagrams([]))
def sort_array(nums:list, ascending: bool = True) -> list:
    return sorted(nums, reverse=not ascending)

def sort_odds_before_evens(nums:list) ->list:
    odds = [n for n in nums  if n%2 != 0]

scheme = "https"
host = "api.example.com"
path  = "users/profile"
params = {"id":"42", "role":"admin", "active":"true"}
from urllib.parse import urlencode
def create_url(scheme:str, host:str, path:str, params: dict) ->str:
    base = f"{scheme}://{host}/{path}"
    query = urlencode(params)
    full_url = f"{base}?{query}"
    return full_url

from urllib.parse import urlparse, parse_qs
def parse_url(url:str) -> dict:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    flat = {k:v[0] for k, v in params.items()}
    return {
        "scheme":parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
        "params": flat,
        "fragment" :parsed.fragment
    }
url = "https://api.example.com:8080/users/profile?id=42&role=admin#section1"
result = parse_url(url)
for key, value in result.items():
    print()
def word_frequenct(sentence:str)->dict:
    words = sentence.split()
    freq = {}
    for word in words:
        freq[word] = freq.get(word, 0) + 1
    return freq
def is_anagram(s:str, t:str) ->bool:
    if len(s) != len(t):
        return False
    count = {}
    for ch in s:
        count[ch] = count.get(ch, 0) + 1
    for ch in s:
        count[ch] = count.get(ch, 0) - 1

    return all(v == 0 for v in count.values())

def is_palindrome(s:str) -> bool:
    s = s.lower().replace(" ", "")
    left, right = 0, len(s)-1

    while left < right:
        if s[left] != s[right]:
            return False
        left +=1
        right -=1
    return True

def reverse_string(s, str)->str:
    stack = []
    for ch in s:
        stack.append(ch)
    result = ""
    while stack:
        result +=stack.pop()
    return result
