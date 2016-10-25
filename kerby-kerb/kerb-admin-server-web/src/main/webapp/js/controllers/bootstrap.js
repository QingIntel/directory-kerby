'use strict';
/* Controllers */
  // bootstrap controller
  //Header
  app.controller('HeaderCtrl', ['$scope', function($scope) {
      $scope.myHeader = {
        name : 'KERBY',
        userName : 'CHEN'
      }

   }]);

   //ngDialog
   app.controller('MainCtrl', function ($scope, $http, $rootScope, $state, ngDialog, $timeout) {
       $rootScope.jsonData = '{"foo": "bar"}';
       $rootScope.theme = 'ngdialog-theme-default';

       $scope.openAdd = function() {
           console.log('Time changed to: ');
           ngDialog.open({
             template: 'addDialogId', //use template id defined in HTML
             className: 'ngdialog-theme-plain',
             closeByEscape : true,
             controller: 'MainCtrl',
             width: 550,
             height: 650
           });
       };

       $scope.openRename = function() {
          if ($scope.gridOptions.selectedItems.length == 1) {
             $scope.oldPrincipalName = $scope.gridOptions.selectedItems[0].principalName;
             ngDialog.open({
                 template: 'renameDialogId', //use template id defined in HTML
                 className: 'ngdialog-theme-plain',
                 closeByEscape : true,
                 controller: 'MainCtrl',
                 width: 550,
                 data: 'oldPrincipalName',
                 scope: $scope,
                 height: 650
             });
          } else {
            $scope.message = "Can and can only choose one record!";
            ngDialog.open({
                 template: 'promptDialogId', //use template id defined in HTML
                 className: 'ngdialog-theme-plain',
                 closeByEscape : true,
                 controller: 'MainCtrl',
                 scope: $scope,
                 data: 'message',
                 width: 350,
                 height: 650
            });
          }
       };

        $scope.openDelete = function() {
          $scope.oldPrincipalName = $scope.gridOptions.selectedItems[0].principalName;

          ngDialog.open({
            template: 'deleteDialogId', //use template id defined in HTML
            className: 'ngdialog-theme-plain',
            closeByEscape : true,
            controller: 'MainCtrl',
            data: 'oldPrincipalName',
            width: 350,
            scope: $scope,
            height: 350
          });
        };

        $scope.addPrincipal = function(principalName,password,passwordAgain) {
          $state.go('app.menu.kadmin');
          if (password == passwordAgain) {
              $http.get("Add.do?principalName=" + principalName + "&password=" + password).success(function (largeLoad) {
                   ngDialog.close();
                   $state.go('app.dashboard-v1');
              });
          } else {
              //console.log("The two passwords don't match!");
              $scope.message = "The two passwords don't match!";
              ngDialog.open({
                   template: 'promptDialogId', //use template id defined in HTML
                   className: 'ngdialog-theme-plain',
                   closeByEscape : true,
                   controller: 'MainCtrl',
                   scope: $scope,
                   data: 'message',
                   width: 350,
                   height: 650
              });
          }
        };

        $scope.renamePrincipal = function(oldPrincipalName,newPrincipalName) {
          $state.go('app.menu.kadmin');
          $http.get("Rename.do?oldPrincipalName=" + oldPrincipalName + "&newPrincipalName=" + newPrincipalName).success(function (largeLoad) {
              ngDialog.close();
              $state.go('app.dashboard-v1');
          });
        };

        $scope.deletePrincipal = function(principalName) {
          $state.go('app.menu.kadmin');
          $http.get("Delete.do?principalName=" + principalName).success(function (largeLoad) {
              ngDialog.close();
              $state.go('app.dashboard-v1');
          });
        };
   });








