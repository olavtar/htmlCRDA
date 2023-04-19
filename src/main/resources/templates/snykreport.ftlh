<html xmlns="http://www.w3.org/1999/html">
<head>
    <#include "patternfly.ftlh">
    <#include "patternfly-addons.ftlh">
<#--    <#include "patternfly-icons.ftlh">-->
<#--    <#include "patternfly-pf-icons.ftlh">-->
<#--    <#include "patternfly-fa-icons.ftlh">-->

    <#include "fontawesome.ftlh">
    <#include "snykstyles.ftlh">
<#--    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous">-->

</head>
<body>

    <h1 class="pf-c-title pf-m-3xl">${securityTitle}</h1>
    <div>${securityDesc}</div>
    <h3>Total Vulnerabilities: ${issues?size}</h3>
    <h3>Vulnerable Dependencies: ${mavenObject.countVulnerableDependencies()}</h3>
    </br>


<#--    <h3>Root Pkg Name: ${mavenObject.pkgName}</h3>-->
<hr class="pf-c-divider" />
</br>
</br>
    <h1 class="pf-c-title pf-m-xl">${subTitle}</h1>
    <div>${subDescription}</div>

</br>

    <#assign numOfPkg = 0>
        <#list mavenObject.dependencies as mavenPackage>
            <#if (mavenPackage.countDirectVulnerabilities() != 0 || mavenPackage.countTransitiveVulnerabilities() != 0) >
                <#assign numOfPkg++>
                <button class="accordion" >#${numOfPkg} : ${mavenPackage.pkgName}</button>
                <div class="panel2">
                    <p>Details of the dependency: <span class="pf-u-font-weight-bold">${mavenPackage.pkgName}</span></p>
                    <li>Current Version: ${mavenPackage.pkgVersion}</li>
                    <li># Direct Vulnerabilities: ${mavenPackage.countDirectVulnerabilities()}</li>
                    <li># Transitive Vulnerabilities: ${mavenPackage.countTransitiveVulnerabilities()}</li>
                    <#if (mavenPackage.countDirectVulnerabilities() != 0) >
                        <li>Highest CVSS Score: ${mavenPackage.getHighestVulnerability().cvssScore}/10</li>
                        <li>Highest Severity Vulnerability: ${mavenPackage.getHighestVulnerability().id}</li>
                    </#if>
                    <#if (mavenPackage.vulnerabilities?size != 0) >
                        <p>
                        <li class="pf-u-font-weight-bold">Vulnerabilities:</li>
                        <#list mavenPackage.vulnerabilities as vulnerability>
                        <ul class="pf-c-list">
                            <#if (vulnerability.severity == "high") >
                                <span class="pf-c-label pf-m-red">
                            </#if><#if (vulnerability.severity == "medium") >
                                <span class="pf-c-label pf-m-orange">
                            </#if>
                                    <#if (vulnerability.severity == "low") >
                                <span class="pf-c-label pf-m-gold">
                            </#if>
                            <span class="pf-c-label__content">
                                ${vulnerability.severity} - ${vulnerability.title} - ${vulnerability.cvssScore}
                                    - ${vulnerability.id}
                            </span>
                                </span>
                        </ul>
                        </#list>
                        </p>
                    </#if>
                    <p>
                    <li class="pf-u-font-weight-bold">Transitive Dependencies with vulnerabilites: </li></p>
                        <#list mavenPackage.getVulnerableTransitiveDeps() as transDependency>
                            <#assign barNum = transDependency.getHighestVulnerability().cvssScore *10>
                            <#if (transDependency.countDirectVulnerabilities() != 0 ) >
                        <button class="accordion">${transDependency?counter} : ${transDependency.pkgName}</button>
                        <div class="panel2">
                                <p>Dependency: ${transDependency.pkgName}</p>
                                <li>Current Version: ${transDependency.pkgVersion}</li>
                                <li># Direct Vulnerabilities: ${transDependency.countDirectVulnerabilities()}</li>
                                <li>Highest CVSS Score: ${transDependency.getHighestVulnerability().cvssScore}
                            <div
                                    class="pf-c-progress pf-m-outside pf-m-sm"
                                    id="progress-outside-static-width-5-example"
                                    style="--pf-c-progress__measure--m-static-width--MinWidth: 170ch;"
                            >
                                <div
                                        class="pf-c-progress__description"
                                        id="progress-outside-static-width-5-example-description"
                                ></div>
                                <div class="pf-c-progress__status" aria-hidden="true">
                                    <span class="pf-c-progress__measure pf-m-static-width">${transDependency.getHighestVulnerability().cvssScore}/10</span>
                                </div>
                                <div
                                        class="pf-c-progress__bar"
                                        role="progressbar"
                                        aria-valuemin="0"
                                        aria-valuemax="10"
                                        aria-valuenow="5"
                                        aria-label="Progress status"
                                >
                                    <div class="pf-c-progress__indicator" style="width:${barNum}%;"></div>
                                </div>
                            </div>
                                </li>
                                <li>Highest Severity Vulnerability: ${transDependency.getHighestVulnerability().id}</li>
                            <li class="pf-u-font-weight-bold">Vulnerabilities:</li>
                                    <#list transDependency.vulnerabilities as transVulnerability>
                            <ul class="pf-c-list">
                                <#if (transVulnerability.severity == "high") >
                                <span class="pf-c-label pf-m-red">
                            </#if><#if (transVulnerability.severity == "medium") >
                                <span class="pf-c-label pf-m-orange">
                            </#if>
                                    <#if (transVulnerability.severity == "low") >
                                <span class="pf-c-label pf-m-gold">
                            </#if>
                            <span class="pf-c-label__content">
                                ${transVulnerability.severity} - ${transVulnerability.title}
                                            - ${transVulnerability.cvssScore} - ${transVulnerability.id}
                                </span>
                                </span>
                            </ul>
                                    </#list>
                                </p>
                        </div>
                            </#if>
                        </#list>
                </div>

            </#if>
        </#list>
</div>
</div>

<script>
    // var acc = document.getElementsByClassName("accordion");
    // var i;
    //
    // for (i = 0; i < acc.length; i++) {
    //     acc[i].addEventListener("click", function() {
    //         this.classList.toggle("active");
    //         var panel = this.nextElementSibling;
    //         if (panel.style.maxHeight) {
    //             panel.style.maxHeight = null;
    //         } else {
    //             panel.style.maxHeight = panel.scrollHeight + "px";
    //         }
    //     });
    // }

    var acc = document.getElementsByClassName("accordion");
    var i;

    for (i = 0; i < acc.length; i++) {
        acc[i].addEventListener("click", function () {
            this.classList.toggle("active");
            var panel = this.nextElementSibling;
            if (panel.style.display === "block") {
                panel.style.display = "none";
            } else {
                panel.style.display = "block";
            }
        });
    }
</script>

</body>
</html>