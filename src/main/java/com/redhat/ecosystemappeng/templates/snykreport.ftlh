<html>
<head>
    <#include "snykstyles.ftlh">
</head>
<body>

<button class="tablink" onclick="openPage('redhat', this, 'red')" id="defaultOpen">Red Hat</button>
<button class="tablink" onclick="openPage('snyk', this, 'green')">Snyk</button>
<button class="tablink" onclick="openPage('tidelift', this, 'blue')">Tidelift</button>

<div id="redhat" class="tabcontent">
    <h3>Trusted Content data goes here...</h3>
<#--    <#list issuesData as key, value>-->
<#--        <li>${key}</li>-->
<#--        <p>packageName: ${value.packageName}</p>-->
<#--        <p>cvssScore: ${value.cvssScore}</p>-->
<#--        <p>severity: ${value.severity}</p>-->
<#--    </#list>-->
</div>

<div id="snyk" class="tabcontent">
    <h3>Total Vulnerabilities: ${issues?size}</h3>
<#--    <ul>-->
<#--        <#list mavenPackageList as mavenPackage>-->
<#--            <li>${mavenPackage_index + 1}. Commonly Known Vulnerabilities: ${mavenPackage.pkgName}</li>-->
<#--            <p>Highest Severity Vulnerability: ${mavenPackage.issueId}</p>-->
<#--            <p>Highest CVSS Score: ${mavenPackage.cvssScore}/10</p>-->
<#--            <p>Vulnerabilities: ${mavenPackage.severity} - ${mavenPackage.title}</p>-->
<#--            <p>Current Version: ${mavenPackage.pkgVersion}</p>-->
<#--            <p>Recommended Version:</p>-->
<#--            <p># Direct Vulnerabilities:</p>-->
<#--            <p># Transitive Vulnerabilities:</p>-->

<#--        </#list>-->
<#--    </ul>-->
    <#list mavenPackageList as key, value>
        <li>ModuleName: ${key}</li>
        <p>cvssScore: ${value.cvssScore}</p>
        <p>id: ${value.issueId}</p>
        <p># Direct Vulnerabilities: ${value.countDirectDeps}</p>
        <p>Current Version: ${value.pkgVersion}</p>

<#--        <#assign fixedInArray = [value.fixedIn]>-->
<#--        <p>Recommended version:-->
<#--        <#list fixedIn as version>-->
<#--            <li>${version}</li>-->
<#--        </#list></p>-->
    </#list>
</div>

<div id="tidelift" class="tabcontent">
    <h3>Tidelift data goes here...</h3>
</div>

<script>
    function openPage(pageName,elmnt,color) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tablink");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].style.backgroundColor = "";
        }
        document.getElementById(pageName).style.display = "block";
        elmnt.style.backgroundColor = color;
    }

    // Get the element with id="defaultOpen" and click on it
    document.getElementById("defaultOpen").click();
</script>

</body>
</html>