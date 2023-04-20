<html xmlns="http://www.w3.org/1999/html">
<head>
<#--    <#include "patternfly.min.ftlh">-->
<#--    <#include "patternfly-addons.ftlh">-->
    <#include "snykstyles.ftlh">
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="fonts.css" />
    <!-- Include latest PatternFly CSS via CDN -->
    <link
            rel="stylesheet"
            href="https://unpkg.com/@patternfly/patternfly/patternfly.css"
            crossorigin="anonymous"
    />
    <link rel="stylesheet" href="style.css" />
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css" integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2" crossorigin="anonymous">

</head>
<body>

<div class="pf-c-card">
    <div class="pf-c-card__title">
        <span class="pf-c-icon">
	    <i class="fa fa-shield-alt" aria-hidden="true"></i>
	</span>
        ${securityTitle}</div>
    <div class="pf-c-card__body">${securityDesc}
        <h3>Total Vulnerabilities: ${issues?size}</h3>
        <h3>Vulnerable Dependencies: ${mavenObject.countVulnerableDependencies()}</h3>
    </div>
</div>


    <h1 class="pf-c-title pf-m-3xl">${securityTitle}</h1>
    <div>${securityDesc}</div>
    <h3>Total Vulnerabilities: ${issues?size}</h3>
    <h3>Vulnerable Dependencies: ${mavenObject.countVulnerableDependencies()}</h3>
    </br>


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

<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js" integrity="sha384-DfXdz2htPH0lsSSs5nCTpuj/zy4C+OGpamoFVy38MVBnE+IbbVYUew+OrCXaRkfj" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ho+j7jyWK8fNQe+A12Hb8AhRq26LrZ/JpcUGGOn+Y7RsweNrtN/tE3MoK7ZeZDyx" crossorigin="anonymous"></script>
</body>
</html>