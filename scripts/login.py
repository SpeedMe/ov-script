import sys
from werkzeug.security import check_password_hash
if check_password_hash(sys.argv[1], sys.argv[2]):
	print 'ok'
else:
	print 'ko'