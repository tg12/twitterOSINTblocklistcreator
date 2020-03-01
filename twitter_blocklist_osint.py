from datetime import datetime, timedelta
import pprint
import re
import sys
import tweepy
from tweepy import Cursor
pp = pprint.PrettyPrinter(indent=4)

# build a table mapping all non-printable characters to None
NOPRINT_TRANS_TABLE = {
    i: None for i in range(0, sys.maxunicode + 1) if not chr(i).isprintable()
}


def make_printable(s):
    """Replace non-printable characters in a string."""

    # the translate method on str removes characters
    # that map to None from the string
    return s.translate(NOPRINT_TRANS_TABLE)


def remove_duplicates(lst):
    res = []
    for x in lst:
        if x not in res:
            res.append(x)
    return res


# Twitter consumer key, consumer secret, access token, access secret
CKEY = ""
CSECRET = ""
ATOKEN = ""
ASECRET = ""

auth = tweepy.OAuthHandler(CKEY, CSECRET)
auth.set_access_token(ATOKEN, ASECRET)
auth_api = tweepy.API(auth)

# add your favourite Infosec Twitter Users, This bit will be a community effort the ones I found I put here
users_to_follow = ["bad_packets", "phishingreel"]
BAD_IPS = []
BAD_URLS = []
#adjust days to hours, minutes etc for more realtime updates
END_DATE = datetime.utcnow() - timedelta(days=1)

###########################################################################
###########################################################################
###########################################################################
###########################################################################

for each in users_to_follow:
    for status in Cursor(auth_api.user_timeline, id=each).items():
        if status.created_at < END_DATE:
            break
        # print(status.text)
        t = status.text
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', t)
        BAD_IPS.extend(ip)

print(BAD_IPS)

###########################################################################
###########################################################################
###########################################################################
###########################################################################

for each in users_to_follow:
    for status in Cursor(auth_api.user_timeline, id=each).items():
        if status.created_at < END_DATE:
            break
        t = make_printable(str(status.text))
        badurl = re.findall(r'(https?://\S+)', t)
        BAD_URLS.extend(badurl)

BAD_URLS = sorted(remove_duplicates(BAD_URLS))
# cleanup rules
BAD_URLS = [x for x in BAD_URLS if not x.startswith(
    'https://t.co/')]  # remove the twitter short url
BAD_URLS = [x for x in BAD_URLS if not x.endswith(
    'Suspected')]  # remove user rule
BAD_URLS = [x for x in BAD_URLS if not x.endswith(
    'Confirmed')]  # remove user rule
BAD_URLS = [x for x in BAD_URLS if not x.endswith(
    'Potential')]  # remove user rule
BAD_URLS = [x for x in BAD_URLS if not x.endswith(
    'Exploit')]  # remove user rule
# add more


with open('blocklist.txt', 'a', errors="ignore") as f:
    datestamp = "##added:" + str(datetime.now().strftime('%Y-%m-%d')) + "\n"
    f.write(datestamp)
    for item in BAD_URLS:
        f.write("%s\n" % item.rstrip())
