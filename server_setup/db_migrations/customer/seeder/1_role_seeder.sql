SET AUTOCOMMIT = 0;
START TRANSACTION;


INSERT INTO `role` (
  id,
  role,
  sub_role
)
VALUES 

(1,"customer","NA"),
(2,"admin","NA"),
(3,"manager","NA"),
(4,"superadmin","NA");