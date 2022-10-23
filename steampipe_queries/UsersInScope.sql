SELECT

    P.name  as "username",
    P.user_email__c as "emailaddress",
    A.serial_number__c as "serialnumber",

    O.Name as "Organization",
    T.Name as "Team"

FROM salesforce_krow__project_resources__c P

LEFT JOIN salesforce_fixed_asset__c A
    ON A.project_resource__c = P.id 
    AND A.is_deleted = false AND A.type__c = 'Laptop'

INNER JOIN salesforce_krow__organization__c O 
    ON O.id = P.krow__organization__c
    AND O.is_deleted = false

INNER JOIN salesforce_krow__team__c T
    ON T.id = P.krow__team__c
    AND T.is_deleted = false

WHERE
    P.is_deleted = false
AND
(
    ( O.Name = 'Some Organisational Name'  AND T.Name = 'Some Organisational Group' ) OR -- Some Organisational Name
)


