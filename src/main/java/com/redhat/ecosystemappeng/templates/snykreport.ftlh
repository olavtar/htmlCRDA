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
    <h3>Vulnerable Dependencies: ${mavenObject.countVulnerableDependencies()}</h3>
    <h3>Root Pkg Name: ${mavenObject.pkgName}</h3>
    <ul>
        <#list mavenObject.dependencies as mavenPackage>
<#--        <#assign directVul = ${mavenPackage.countDirectVulnerabilities()} />-->
<#--        <#assign transitiveVul = ${mavenPackage.countTransitiveVulnerabilities()} />-->
            <#if (mavenPackage.countDirectVulnerabilities() != 0 || mavenPackage.countTransitiveVulnerabilities() != 0) >
                <li>Dependency: ${mavenPackage.pkgName}</li>
                <p>Current Version: ${mavenPackage.pkgVersion}</p>
                <p># Direct Vulnerabilities: ${mavenPackage.countDirectVulnerabilities()}</p>
                <p># Transitive Vulnerabilities: ${mavenPackage.countTransitiveVulnerabilities()}</p>
                <#if (mavenPackage.countDirectVulnerabilities() != 0) >
                    <p>Highest CVSS Score: ${mavenPackage.getHighestVulnerability().cvssScore}</p>
                    <p>Highest Severity Vulnerability: ${mavenPackage.getHighestVulnerability().id}</p>
                 </#if>
                <p>Vulnerabilities:
                <ul>
                    <#list mavenPackage.vulnerabilities as vulnerability>
                        <p>${vulnerability.severity}  - ${vulnerability.title} - ${vulnerability.cvssScore} - ${vulnerability.id}</p>
                    </#list>
                </ul>
                </p>
                <p>Transitive Dependencies with vulnerabilites: </p>
                <ul>
                    <#list mavenPackage.getVulnerableTransitiveDeps() as transDependency>
                        <#if (transDependency.countDirectVulnerabilities() != 0 ) >
                            <li>Dependency: ${transDependency.pkgName}</li>
                            <p>Current Version: ${transDependency.pkgVersion}</p>
                            <p># Direct Vulnerabilities: ${transDependency.countDirectVulnerabilities()}</p>
                            <p>Highest CVSS Score: ${transDependency.getHighestVulnerability().cvssScore}</p>
                            <p>Highest Severity Vulnerability: ${transDependency.getHighestVulnerability().id}</p>
                            <p>Vulnerabilities:
                                <ul>
                                    <#list transDependency.vulnerabilities as transVulnerability>
                                        <p>${transVulnerability.severity}  - ${transVulnerability.title} - ${transVulnerability.cvssScore} - ${transVulnerability.id}</p>
                                    </#list>
                                </ul>
                            </p>
                        </#if>
                    </#list>
                </ul>
            </#if>
        </#list>
    </ul>
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