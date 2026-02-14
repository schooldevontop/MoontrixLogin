package fr.lordmoontrix.moontrixlogin.util;

import java.lang.reflect.Method;
import java.util.function.Consumer;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

public final class SchedulerUtil {
    private static final Method GET_GLOBAL_SCHEDULER = findMethod(
        Bukkit.getServer().getClass(), "getGlobalRegionScheduler");
    private static final Method GET_PLAYER_SCHEDULER = findMethod(Player.class, "getScheduler");

    private SchedulerUtil() {
    }

    public static void runGlobal(Plugin plugin, Runnable task) {
        if (!tryGlobalRun(plugin, task)) {
            Bukkit.getScheduler().runTask(plugin, task);
        }
    }

    public static void runGlobalLater(Plugin plugin, Runnable task, long delayTicks) {
        if (!tryGlobalRunDelayed(plugin, task, delayTicks)) {
            Bukkit.getScheduler().runTaskLater(plugin, task, delayTicks);
        }
    }

    public static void runGlobalTimer(Plugin plugin, Runnable task, long delayTicks, long periodTicks) {
        if (!tryGlobalRunAtFixedRate(plugin, task, delayTicks, periodTicks)) {
            Bukkit.getScheduler().runTaskTimer(plugin, task, delayTicks, periodTicks);
        }
    }

    public static void runAtPlayer(Plugin plugin, Player player, Runnable task) {
        if (!tryPlayerRun(player, plugin, task)) {
            Bukkit.getScheduler().runTask(plugin, task);
        }
    }

    public static void runAtPlayerLater(Plugin plugin, Player player, Runnable task, long delayTicks) {
        if (!tryPlayerRunDelayed(player, plugin, task, delayTicks)) {
            Bukkit.getScheduler().runTaskLater(plugin, task, delayTicks);
        }
    }

    private static boolean tryGlobalRun(Plugin plugin, Runnable task) {
        if (GET_GLOBAL_SCHEDULER == null) {
            return false;
        }
        try {
            Object scheduler = GET_GLOBAL_SCHEDULER.invoke(Bukkit.getServer());
            Method run = findMethod(scheduler.getClass(), "run", Plugin.class, Consumer.class);
            if (run == null) {
                return false;
            }
            run.invoke(scheduler, plugin, (Consumer<Object>) t -> task.run());
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private static boolean tryGlobalRunDelayed(Plugin plugin, Runnable task, long delayTicks) {
        if (GET_GLOBAL_SCHEDULER == null) {
            return false;
        }
        try {
            Object scheduler = GET_GLOBAL_SCHEDULER.invoke(Bukkit.getServer());
            Method run = findMethod(scheduler.getClass(), "runDelayed", Plugin.class, Consumer.class, long.class);
            if (run == null) {
                return false;
            }
            run.invoke(scheduler, plugin, (Consumer<Object>) t -> task.run(), delayTicks);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private static boolean tryGlobalRunAtFixedRate(Plugin plugin, Runnable task, long delayTicks, long periodTicks) {
        if (GET_GLOBAL_SCHEDULER == null) {
            return false;
        }
        try {
            Object scheduler = GET_GLOBAL_SCHEDULER.invoke(Bukkit.getServer());
            Method run = findMethod(scheduler.getClass(), "runAtFixedRate",
                Plugin.class, Consumer.class, long.class, long.class);
            if (run == null) {
                return false;
            }
            run.invoke(scheduler, plugin, (Consumer<Object>) t -> task.run(), delayTicks, periodTicks);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private static boolean tryPlayerRun(Player player, Plugin plugin, Runnable task) {
        if (GET_PLAYER_SCHEDULER == null) {
            return false;
        }
        try {
            Object scheduler = GET_PLAYER_SCHEDULER.invoke(player);
            Method run = findMethod(scheduler.getClass(), "run", Plugin.class, Consumer.class);
            if (run == null) {
                return false;
            }
            run.invoke(scheduler, plugin, (Consumer<Object>) t -> task.run());
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private static boolean tryPlayerRunDelayed(Player player, Plugin plugin, Runnable task, long delayTicks) {
        if (GET_PLAYER_SCHEDULER == null) {
            return false;
        }
        try {
            Object scheduler = GET_PLAYER_SCHEDULER.invoke(player);
            Method run = findMethod(scheduler.getClass(), "runDelayed", Plugin.class, Consumer.class, long.class);
            if (run == null) {
                return false;
            }
            run.invoke(scheduler, plugin, (Consumer<Object>) t -> task.run(), delayTicks);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private static Method findMethod(Class<?> type, String name, Class<?>... params) {
        try {
            return type.getMethod(name, params);
        } catch (NoSuchMethodException ex) {
            return null;
        }
    }
}
