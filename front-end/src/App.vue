<template>
  <div id="app">
    <nav class="navbar navbar-expand navbar-dark bg-dark">
      <router-link to="/" class="navbar-brand">bezKoder</router-link>
      <div class="navbar-nav mr-auto">
        <li class="nav-item">
          <router-link to="/tutorials" class="nav-link">Tutorials</router-link>
        </li>
        <li class="nav-item">
          <router-link to="/add" class="nav-link">Add</router-link>
        </li>
      </div>

      <!--      유저가 로그인 안하면 아래 메뉴가 보임 : 로그인 메뉴가 보임-->
      <div v-if="!currentUser" class="navbar-nav ml-auto">
        <li class="nav-item">
          <router-link to="/register" class="nav-link">
            <!--            웹 아이콘 추가 : user -->
            <font-awesome-icon icon="user-plus" ></font-awesome-icon>
            Sign Up
          </router-link>
        </li>
        <li class="nav-item">
          <router-link to="/login" class="nav-link">
            <!--            웹 아이콘 추가 : user -->
            <font-awesome-icon icon="sign-in-alt" ></font-awesome-icon>
            Login
          </router-link>
        </li>
      </div>

<!--      유저가 로그인 하면 아래 메뉴가 보임 : 로그아웃 메뉴가 보임 -->
      <div v-if="currentUser" class="navbar-nav ml-auto">
        <li class="nav-item">
          <router-link to="/profile" class="nav-link">
<!--            웹 아이콘 추가 : user -->
            <font-awesome-icon icon="user" ></font-awesome-icon>
            {{ currentUser.username }}
          </router-link>
        </li>
        <li class="nav-item">
          <a href @click.prevent="logOut" class="nav-link">
<!--            웹 아이콘 추가 : LogOut -->
            <font-awesome-icon icon="sign-out-alt"></font-awesome-icon>
            LogOut
          </a>
        </li>
      </div>

    </nav>

    <div class="container mt-3">
      <router-view />
    </div>
  </div>
</template>

<script>
export default {
  // html에서 변수처럼 호출 : 뒤에 () 붙이면 안됨 예) currentUser
  // 속도는 computed 빠름
  computed: {
    currentUser() {
      // 공유저장소의 전역변수(공유변수 : user )
      // 자동으로 로그인되었으면 loggedIn = true, user객체 있음
      // 아니면 loggedIn = false, user객체 = null
      return this.$store.state.auth.user;
      // return true; // 테스트용
    }
  },
  // html에서 함수처럼 호출 : 뒤에 () 붙음 예) logOut(), logOut
  methods: {
    logOut() {
      // dispatch 호출하는 메소드 : actions 있는 메소드를 호출함
      this.$store.dispatch("auth/logout");
    //   로그아웃 후 이동할 페이지 지정 : login 페이지
      this.$router.push("/login")
    }
  }
};
</script>










