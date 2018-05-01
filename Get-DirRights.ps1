<#
.SYNOPSIS
-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-



                        created by WHITETRA$H
        ---------------------------------------------------------
                                            


        .\rightsCheck [directory], [-r], [-f], [path of out-file]

        [-r]  recursion
        [-f] out in file


        example:
            .\rightsCheck.ps1 \\srv\ok -r -f srvOKrights.csv

                                            

        ---------------------------------------------------------





-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-



#>


Param($dirPath="\\srv\ИТ", [switch] $r, [Switch] $f,  $outFilePath='.\audit_prav_dostupa.csv')
    # $dirPath - папка, для которой нужно посчитать права
    # $f - ключ вывода в файл
    # $r - ключ рекурсивного вывода прав вложенных папок
    # $outFilePath - выходной файл. по умолчанию сохраняется туда, где лежит скрипт



#функция превращения 'WORKGROUP\ПЭО_все' в 'ПЭО_все'
function Get-CutName($name){
    $name.Substring($name.indexOf('\')+1, $name.Length - $name.indexOf('\') - 1)
}



#функция возвращает Полное имя пользователя("ArtukhovskayaEU"). аргумент $loginName - имя для входа( "pc123" )--------------------------------------
function userFullName($loginName){
    try{
        $netUser = net user /domain $loginName
        $FullName = $netUser[3].substring($netUser[3].lastIndexOf(" ")+1, $netUser[3].length - ($netUser[3].lastIndexOf(" ")+1) )
        return $FullName
    }
    catch{
        $loginName
    }
}


#функция парсинга пользователей из массива строк, получаемого командой "net group /domain огк_все". пример вызова: userParsing(net group /domain огк_все) ). пример вывода:  group:user1:user2:user3.
function userParsing($a){
    $return_string ="" #строка, содержащая список пользователей группы безопасности
    for($i=8; $i -lt $a.Count - 2; $i=$i+1)
    {
        $return_string += ( userFullName( $a[$i].Substring(0, $a[$i].IndexOf(" ")) ) ) #1
        $return_string += ":" 

        if( $a[$i].length -ge 50 ){
            $a[$i] = $a[$i].Remove(0, 25) 
            $return_string += ( userFullName( $a[$i].Substring(0, $a[$i].IndexOf(" ")) ) + ":" ) #2
            $return_string += ":"
        }

        if( $a[$i].length -eq 50 ){
            $a[$i] = $a[$i].Remove(0, 25)
            $return_string += ( userFullName( $a[$i].Substring(0, $a[$i].IndexOf(" ")) ) + ":" ) #3
            $return_string += ":"
        }

    }
    $return_string
}


#функция получения массива "чистых" Имён групп домена
function getNetGroupDomain{
    $netGroups = net group /domain
    $return_groups = "","","" #возвращаемый массив, который будет содержать только имена групп
    $i = 6
    do #цикл преобразования имён групп. в массиве $return_groups хранятся имена групп
    {
        $return_groups += $netGroups[$i].Remove(0,1)
        $i = $i + 1
    }
    while ( $netGroups[$i] -ne "Команда выполнена успешно." )
    $p = $return_groups[3..$return_groups.Count].Clone() #т.к. массив задается тремя пробелами( $return_groups = "","","" ), то удаляем их
    return $p
}


#функция получения полного списка групп безопасности и их пользователей из контроллера домена
function getUsersOfDomainGroups{
    $domainGroups = getNetGroupDomain #массив групп пользователей домена

    for( $i = 0; $i -lt $domainGroups.Count; $i++ ){ #дописывание пользователей в строку с группой
       $netGroupDomain = net group /domain $domainGroups[$i]
       if ($netGroupDomain[8] -ne "Команда выполнена успешно.")
       {
            $domainGroups[$i] = $domainGroups[$i] + ":" + (userParsing($netGroupDomain))
       }
    
    }

    return $domainGroups
}


#функция получения пользователей группы безопасности $userOrGroup ("ОГТ_все", "pc123")
#Если аргументом передан пользователь, то функция возвращает Имя пользователя и права. Если аргумент - группа безопасности, то возвращается список пользователей этой группы с правами доступа
function getGroupUsers($userOrGroup){
    $rights = $userOrGroup.FileSystemRights.ToString()
    $cutName = get-CutName($userOrGroup.IdentityReference.ToString())
    
    for($i=1; $i -le $UsersOfDomainGroups.Count; $i++){
        if ($UsersOfDomainGroups[$i] -like $cutName +'*'){
            return $UsersOfDomainGroups[$i] + ' === ' + $rights
        }
    }
    $fullName = userFullName($cutName)
    return $fullName + ' === ' + $rights #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
}



#функция формирования полного списка прав для каталога $dirPath
function getListOfRights($dir){
    $lOR = "", "", $dir, "----------------"
    $roa = Get-Acl $dir
    ForEach($us in $roa.Access){ 
        $lOR = $lOR + (getGroupUsers($us))
    }
    return $lOR
}


#рекурсивная функция получения прав доступа на подпапки
function getRecursDirRights($dirRec){
    $return_getRecRights = getListOfRights($dirRec)
    if (($r -eq $true) -and (( Get-ChildItem $dirRec -Directory) -ne $null)) { 
        $return_getRecRights += Get-ChildItem $dirRec -Directory | ForEach-Object { getRecursDirRights($_.PsPath.ToString().Remove(0,38)) }
    }
    return $return_getRecRights
}


#Главная функция, из которой всё начинает работать
function Get-DirRights($dirPath="\\srv\ИТ", [switch] $r, [Switch] $f,  $outFilePath='.\audit_prav_dostupa.csv'){
<#
.SYNOPSIS
-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-



                                                            created by WHITETRA$H
                                            ---------------------------------------------------------
                                            


                                            .\rightsCheck [directory], [-r], [-f], [path of out-file]

                                            [-r]  recursion
                                            [-f] out in file


                                            example:
                                                .\rightsCheck.ps1 \\srv\ok -r -f srvOKrights.csv

                                            

                                            ---------------------------------------------------------





-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-$-



#>
    [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("cp866")
    cls

    Write-Host 'ждите...'
    #$UsersOfDomainGroups = getUsersOfDomainGroups #-Encoding UTF8     #список групп безопасности и пользователей, входящих в группы
    #эта функция долго выполняется.

    cls
    $glor = getRecursDirRights($dirPath) #в $glor присваивается полный список прав
    $listOfRights = "", "ПРАВА ДОСТУПА К $dirPath", "--------------------------------", "" + $glor
    
    

    #вывод списка прав. если скрипт вызван с ключом -f, то выводится в файл $outFilePath
    if ($f -eq $true) 
        { $listOfRights | Out-File $outFilePath }
    else{ $listOfRights }
}

Get-DirRights #вызов главной функции