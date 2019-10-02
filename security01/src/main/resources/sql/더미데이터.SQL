INSERT INTO SECURED_RESOURCE
(RESOURCE_ID, RESOURCE_NAME, RESOURCE_PATTERN, RESOURCE_TYPE, SORT_ORDER)
VALUES
('R01', 'ANYONE.ALL', 		'/anyone/**', 'URL', 1),
('R02', 'MEMBER.ALL', 		'/member/**', 'URL', 2),
('R03', 'MEMBER.CREATE', 	'/member/create/**', 'URL', 3),
('R04', 'MEMBER.DELETE', 	'/member/delete/**', 'URL', 4),
('R05', 'ADMIN.ALL', 		'/admin/**', 		 'URL', 5);

INSERT INTO SECURED_RESOURCE_AUTHORITY
(RESOURCE_ID, AUTHORITY, `NAME`)
VALUES
('R01', 'ANONYMOUS', 		'아무나'),
('R02', 'MEMBER_ALL', 		'회원중에 최고 권한'),
('R03', 'MEMBER_CREATE', 	'회원 글쓰기 권한'),
('R04', 'MEMBER_DELETE', 	'회원 글쓰기 삭제'),
('R05', 'ADMIN_ALL', 		'관리자 모든 권한');
