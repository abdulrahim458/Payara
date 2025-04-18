<!--

    DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.

    Copyright (c) 2010 Oracle and/or its affiliates. All rights reserved.

    The contents of this file are subject to the terms of either the GNU
    General Public License Version 2 only ("GPL") or the Common Development
    and Distribution License("CDDL") (collectively, the "License").  You
    may not use this file except in compliance with the License.  You can
    obtain a copy of the License at
    https://glassfish.dev.java.net/public/CDDL+GPL_1_1.html
    or packager/legal/LICENSE.txt.  See the License for the specific
    language governing permissions and limitations under the License.

    When distributing the software, include this License Header Notice in each
    file and include the License file at packager/legal/LICENSE.txt.

    GPL Classpath Exception:
    Oracle designates this particular file as subject to the "Classpath"
    exception as provided by Oracle in the GPL Version 2 section of the License
    file that accompanied this code.

    Modifications:
    If applicable, add the following below the License Header, with the fields
    enclosed by brackets [] replaced by your own identifying information:
    "Portions Copyright [year] [name of copyright owner]"

    Contributor(s):
    If you wish your version of this file to be governed by only the CDDL or
    only the GPL Version 2, indicate your decision by adding "[Contributor]
    elects to include this software in this distribution under the [CDDL or GPL
    Version 2] license."  If you don't indicate a single choice of license, a
    recipient has the option to distribute your version of this file under
    either the CDDL, the GPL Version 2 or to extend the choice of license to
    its licensees as provided above.  However, if you add GPL Version 2 code
    and therefore, elected the GPL Version 2 license, then the option applies
    only if the new code is made subject to such option by the copyright
    holder.

   Portions Copyright 2016-2025 Payara Foundation and/or its affiliates
-->

<sun:masthead id="Masthead" productImageURL="#{request.contextPath}/resource/community-theme/images/masthead-product_name_open-new.png" 
              style="border-width: 0px"
              productImageDescription="$resource{theme.productName}"
              userInfo="#{sanitisedUserName}"  userInfoLabel="$resource{i18n.masthead.userInfoLabel}"
              roleInfo="#{domainName}" roleInfoLabel="$resource{i18n.masthead.domainInfoLabel}"
              serverInfo="#{hostName}" serverInfoLabel="$resource{i18n.masthead.serverInfoLabel}"
              dateTime="$boolean{false}" notificationMsg="$attribute{null}">
    
    <h:panelGroup layout="block" id="environmentWarningBar" rendered="#{sessionScope.environmentWarningBarEnabled}" style="text-align:center;background-color:#{sessionScope.environmentWarningBarBackgroundColour}">
        <sun:staticText id="environmentWarningBarMessage"
                        style="color:#{sessionScope.environmentWarningBarTextColour};"
                        text="#{sessionScope.environmentWarningBarMessage}"
                        toolTip="#{sessionScope.environmentWarningBarMessage}">
        </sun:staticText>
    </h:panelGroup>

    <!facet utilityBar>
        <sun:panelGroup id="utilityBar">
            <sun:staticText
                style="flex: 1 1 auto; padding: 12px 15px;"
                text="Version #{sessionScope.appServerMajorVersion}">
            </sun:staticText>
            <sun:hyperlink id="homeLink" toolTip="$resource{i18n.homeLinkTooltip}" target="_top" text="$resource{i18n.masthead.Home}" url="#{request.contextPath}/common/index.jsf" />
            <sun:hyperlink id="versionLink" toolTip="$resource{i18n.versionTooltip}" text="$resource{i18n.masthead.Version}"
                onClick="javascript: var versionWin = window.open('#{request.contextPath}/common/version.jsf','VersionWindow','scrollbars,resizable,width=800,height=740,top='+((screen.height - (screen.height/1.618)) - (500/2))+',left='+((screen.width-650)/2) ); versionWin.focus(); return false;" onKeyPress="javascript: return true;" />
            <sun:hyperlink id="enterpriseLink" toolTip="$resource{i18n.enterpriseLinkTooltip}" target="_blank" text="$resource{i18n.masthead.EnterpriseLink}" url="https://www.payara.fish/products/payara-server/" />
            <sun:button id="help" toolTip="$resource{i18n.helpWindowTooltip}" target="_top" text="$resource{i18n.masthead.Help}" onClick="admingui.help.launchHelp(this); return false;" />
            <sun:button id="onlineHelp" toolTip="$resource{i18n.onlineHelpWindowTooltip}" target="_top" text="$resource{i18n.masthead.OnlineHelp}" onClick="admingui.help.launchHelp(); return false;" />
            <sun:button id="logoutLink" rendered="#{showLogoutButton}" toolTip="$resource{i18n.logoutTooltip}" target="_top" text="$resource{i18n.masthead.Logout}"
                onClick="if (!confirm('$resource{i18n.msg.JS.confirmLogout}')) return false;" onKeyPress="javascript: return true;" url="/" >
                    <!command
                        logout();
                        redirect("#{request.contextPath}/common/index.jsf");
                    />
            </sun:button>
            <sun:button id="enableAsadminRecorderLink" rendered="#{showEnableAsadminRecorderButton}" toolTip="$resource{i18n.enableAsadminRecorderToolTip}" target="_top" text="$resource{i18n.masthead.enableAsadminRecorder}"
                        onClick="if (!confirm('$resource{i18n.msg.JS.confirmEnableAsadminRecorder}')) {return false;} else {this.value='$resource{i18n.button.Processing}';}" onKeyPress="javascript: return true;">
                <!command
                setSessionAttribute(key="showEnableAsadminRecorderButton", value="false");
                setSessionAttribute(key="showDisableAsadminRecorderButton", value="true");
                gf.restRequest(endpoint="#{sessionScope.REST_URL}/enable-asadmin-recorder" method="POST");
                redirect("#{request.contextPath}/common/index.jsf");
                />
            </sun:button>
            <sun:button id="disableAsadminRecorderLink" rendered="#{showDisableAsadminRecorderButton}" toolTip="$resource{i18n.disableAsadminRecorderToolTip}" target="_top" text="$resource{i18n.masthead.disableAsadminRecorder}"
                        onClick="if (!confirm('$resource{i18n.msg.JS.confirmDisableAsadminRecorder}')) {return false;} else {this.value='$resource{i18n.button.Processing}';}" onKeyPress="javascript: return true;">
                <!command
                setSessionAttribute(key="showEnableAsadminRecorderButton", value="true");
                setSessionAttribute(key="showDisableAsadminRecorderButton", value="false");
                gf.restRequest(endpoint="#{sessionScope.REST_URL}/disable-asadmin-recorder" method="POST");
                redirect("#{request.contextPath}/common/index.jsf");
                />
            </sun:button>
        </sun:panelGroup>
    </facet>
    <!facet statusArea>
        <sun:panelGroup id="statusPanel" separator="">
            "<span style="margin: 5px 5px 0px 5px">
                <sun:image id="alertImage" rendered="#{sessionScope.restartRequired}" alt="$resource{i18n.masthead.restartRequired}" icon="ALERT_WARNING_MEDIUM"/>
                <sun:hyperlink id="restartLink" rendered="#{sessionScope.restartRequired}"
                               style="color:white; margin-left: 5px;"
                               text="$resource{i18n.masthead.restartRequired}"
                               toolTip="$resource{i18n.masthead.restartStatusMsg}"
                               onMouseOver="window.status='$resource{i18n.masthead.restartStatusMsg}'; return true"
                               onMouseOut="window.status=''; return true"
                               onBlur="window.status=''; return true"
                               onFocus="window.status='$resource{i18n.masthead.restartStatusMsg}'; return true"
                               url="#{request.contextPath}/common/appServer/restart.jsf">
                </sun:hyperlink>
            "</span>
            <!afterCreate
                includeIntegrations(type="org.glassfish.admingui:mastheadStatusArea" root="$this{component}");
            />
        </sun:panelGroup>
    </facet>
</sun:masthead>
