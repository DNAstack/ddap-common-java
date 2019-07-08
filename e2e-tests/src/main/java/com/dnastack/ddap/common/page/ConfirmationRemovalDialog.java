package com.dnastack.ddap.common.page;

import com.dnastack.ddap.common.DdapBy;
import org.openqa.selenium.WebDriver;

public class ConfirmationRemovalDialog {

    private WebDriver driver;

    public ConfirmationRemovalDialog(WebDriver driver) {
        this.driver = driver;
    }

    public AdminListPage confirmForceDelete() {
        driver.findElement(DdapBy.se("accept-btn")).click();
        return new AdminListPage(driver);
    }

    public AdminListPage cancel() {
        driver.findElement(DdapBy.se("cancel-btn")).click();
        return new AdminListPage(driver);
    }
}
